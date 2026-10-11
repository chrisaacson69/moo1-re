"""Sweep 1oom's struct-typed data tables (ship tech, monsters, start ships) against the v1.3 EXEs.

Per record: flatten the initializer to its numeric leaves (pointers/strings dropped, enums and
#defines resolved from 1oom's headers), then byte-search ORION.EXE/STARMAP.EXE for that sequence as
16-bit words and as bytes. One record alone may be a coincidence; the evidence is **stride**: records
of one table found at a constant spacing locate the original table and reveal its real record size
(original fields not in 1oom show up as stride > 1oom's field count).

Per table verdict:
  LOCATED  — ≥ 3 records hit at one constant stride (offset, stride, records matched / total)
  PARTIAL  — some records hit but no consistent stride (listed)
  ABSENT   — no record found (NOT a refutation: computed, different layout, or LBX data)
Writes notes/struct-sweep.md. Usage: py -3 tools/struct_sweep.py
"""
import re, collections, datetime, struct
from common import ONEOOM, ONEOOM_PIN, ROOT, game_dir
from exe_find import EXES

TABLES = [  # (file, symbol) — the struct-typed data tables found in 1oom @42e9c0b
    ("src/game/game_shiptech.c", "tbl_shiptech_weap"),
    ("src/game/game_shiptech.c", "tbl_shiptech_comp"),
    ("src/game/game_shiptech.c", "tbl_shiptech_engine"),
    ("src/game/game_shiptech.c", "tbl_shiptech_armor"),
    ("src/game/game_shiptech.c", "tbl_shiptech_shield"),
    ("src/game/game_shiptech.c", "tbl_shiptech_jammer"),
    ("src/game/game_shiptech.c", "tbl_shiptech_special"),
    ("src/game/game_shiptech.c", "tbl_shiptech_hull"),
    ("src/game/game_parsed.c", "tbl_monster"),
    ("src/game/game_shipdesign.c", "tbl_startship"),
]
MIN_RECORD_VALUES = 4


# ---- symbol resolution ------------------------------------------------------------------------
def strip_comments(s):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", s, flags=re.S)


def safe_eval(expr, sym):
    e = re.sub(r"\b[A-Za-z_]\w*\b", lambda m: str(sym[m.group(0)]) if m.group(0) in sym else m.group(0), expr)
    e = re.sub(r"\(\s*(?:u?int\d+_t|int|unsigned|signed|short)\s*\)", "", e)   # drop C casts
    if re.search(r"[A-Za-z_]", re.sub(r"0[xX][0-9a-fA-F]+|(?<=\d)[uUlL]+", "", e)):
        return None                                   # an identifier survived: unresolved symbol
    try:
        return int(eval(re.sub(r"(?<=[0-9a-fA-F])[uUlL]+\b", "", e).replace("/", "//"), {"__builtins__": {}}))
    except Exception:
        return None


def symbols():
    sym = {"true": 1, "false": 0, "NULL": 0}
    srcs = [strip_comments(f.read_text(encoding="latin1")) for f in (ONEOOM / "src").rglob("*.h")]
    for _ in range(4):                                  # a few passes to resolve forward references
        for s in srcs:
            for m in re.finditer(r"^\s*#define\s+([A-Za-z_]\w*)\s+([^\n]+)$", s, re.M):
                if m.group(1) not in sym and (v := safe_eval(m.group(2), sym)) is not None:
                    sym[m.group(1)] = v
            for m in re.finditer(r"\benum\b[^{;]*\{([^}]*)\}", s):
                n = -1
                for item in m.group(1).split(","):
                    item = item.strip()
                    if not item:
                        continue
                    name, _, val = item.partition("=")
                    name = name.strip()
                    if val:
                        v = safe_eval(val, sym)
                        if v is None:
                            break
                        n = v
                    else:
                        n += 1
                    sym.setdefault(name, n)
    return sym


# ---- initializer parsing ----------------------------------------------------------------------
def initializer(path, symbol):
    s = strip_comments((ONEOOM / path).read_text(encoding="latin1"))
    m = re.search(r"\b" + symbol + r"\s*((?:\[[^\]]*\])+)\s*=\s*\{", s)
    dims = m.group(1).count("[")
    i, depth = m.end() - 1, 0
    for j in range(i, len(s)):
        depth += {"{": 1, "}": -1}.get(s[j], 0)
        if depth == 0:
            return s[i + 1:j], s[:m.start()].count("\n") + 1, dims


def split_top(body):
    """Split a brace body into top-level items."""
    items, depth, cur = [], 0, ""
    for ch in body:
        if ch in "{(":
            depth += 1
        elif ch in "})":
            depth -= 1
        if ch == "," and depth == 0:
            items.append(cur.strip()); cur = ""
        else:
            cur += ch
    if cur.strip():
        items.append(cur.strip())
    return items


def leaves(item):
    item = item.strip()
    if item.startswith("{"):
        return [x for sub in split_top(item[1:-1]) for x in leaves(sub)]
    return [item]


def records(body, dims):
    """Top-level records; a 2-D table (e.g. monster[MONSTER_NUM][DIFFICULTY_NUM]) is flattened one level."""
    top = split_top(body)
    if dims < 2:
        return top
    return [inner for it in top for inner in split_top(it.strip()[1:-1])]


def numeric(rec, sym):
    out = []
    for leaf in leaves(rec):
        if leaf.startswith(("&", '"')) or not leaf:
            out.append(None)                 # pointer / string field: not stored inline as a number
            continue
        out.append(safe_eval(leaf, sym))
    return out


def table_records(path, symbol):
    body, _, dims = initializer(path, symbol)
    return records(body, dims)


def numeric_flat(rec, sym):
    """Numeric fields only, pointers/strings removed (their position in the original is unknown)."""
    return [v for leaf, v in zip(leaves(rec), numeric(rec, sym)) if not leaf.startswith(("&", '"'))]


# ---- search -----------------------------------------------------------------------------------
def runs(vals):
    """Maximal runs of resolved values."""
    cur, out = [], []
    for v in vals + [None]:
        if v is None:
            if len(cur) >= MIN_RECORD_VALUES:
                out.append(cur)
            cur = []
        else:
            cur.append(v)
    return out


def pack(vals, w):
    try:
        return b"".join(struct.pack("<h" if v < 0 else "<H", v) for v in vals) if w == 2 else \
               bytes(v & 0xFF for v in vals) if all(-128 <= v <= 255 for v in vals) else None
    except struct.error:
        return None


def find_all(data, pat):
    out, k = [], data.find(pat)
    while k >= 0 and len(out) < 20:
        out.append(k); k = data.find(pat, k + 1)
    return out


def sweep_table(path, symbol, sym, bins):
    body, line, dims = initializer(path, symbol)
    recs = records(body, dims)
    hits = collections.defaultdict(list)          # (exe, width) -> [(rec_index, offset)]
    unresolved = set()
    for ri, rec in enumerate(recs):
        vals = numeric(rec, sym)
        for leaf, v in zip(leaves(rec), vals):
            if v is None and not leaf.startswith(("&", '"')) and leaf:
                unresolved.add(leaf)
        r = max(runs(vals), key=len, default=None)
        if not r:
            continue
        for exe, data in bins.items():
            for w in (2, 1):
                pat = pack(r, w)
                if pat:
                    for off in find_all(data, pat):
                        hits[(exe, w)].append((ri, off))
    best = None
    for (exe, w), hs in hits.items():
        by_rec = collections.defaultdict(list)
        for ri, off in hs:
            by_rec[ri].append(off)
        # vote on (base, stride): for each pair of records, candidate stride = d_off / d_ri
        votes = collections.Counter()
        ris = sorted(by_rec)
        for a in range(len(ris)):
            for b in range(a + 1, min(a + 4, len(ris))):
                for oa in by_rec[ris[a]]:
                    for ob in by_rec[ris[b]]:
                        d, k = ob - oa, ris[b] - ris[a]
                        if d > 0 and d % k == 0:
                            votes[(oa - ris[a] * (d // k), d // k)] += 1
        for (base, stride), _ in votes.most_common(3):
            matched = [ri for ri in ris if base + ri * stride in by_rec[ri] or
                       any(o - base >= 0 and (o - base) % stride == 0 and (o - base) // stride == ri for o in by_rec[ri])]
            if not best or len(matched) > len(best[4]):
                best = (exe, w, base, stride, matched)
    any_hit = sorted({ri for hs in hits.values() for ri, _ in hs})
    return line, len(recs), best, any_hit, sorted(unresolved)


WINDOWS = (4, 3)   # try 4 consecutive fields; short records (e.g. hulls: 5 values) fall back to 3


def window_sweep(recs_vals, data):
    for w in WINDOWS:
        r = window_sweep_w(recs_vals, data, w)
        if r:
            return r
    return None


def window_sweep_w(recs_vals, data, WINDOW):
    """Fallback for layouts that differ from 1oom's (inserted/reordered/narrower fields): search every
    run of WINDOW consecutive numeric fields as int16, vote (base, stride) separately per window position
    j (field index in 1oom's order), and keep the strongest. -> (j, base, stride, matched_recs) or None."""
    best = None
    maxlen = max((len(v) for v in recs_vals), default=0)
    for j in range(0, max(0, maxlen - WINDOW + 1)):
        by_rec = collections.defaultdict(list)
        for ri, vals in enumerate(recs_vals):
            win = vals[j:j + WINDOW]
            if len(win) < WINDOW or None in win or len(set(win)) < 3:   # low-entropy windows match anywhere
                continue
            pat = pack(win, 2)
            if pat:
                by_rec[ri] = find_all(data, pat)
        votes = collections.Counter()
        ris = sorted(r for r in by_rec if by_rec[r])
        for x in range(len(ris)):
            for y in range(x + 1, min(x + 4, len(ris))):
                for oa in by_rec[ris[x]]:
                    for ob in by_rec[ris[y]]:
                        d, k = ob - oa, ris[y] - ris[x]
                        if d > 0 and d % k == 0:
                            votes[(oa - ris[x] * (d // k), d // k)] += 1
        for (base, stride), _ in votes.most_common(2):
            matched = [ri for ri in ris if base + ri * stride in by_rec[ri]]
            distinct = {tuple(recs_vals[ri]) for ri in matched}   # identical records are one piece of evidence
            if len(distinct) >= 3 and (not best or len(matched) > len(best[3])):
                best = (j, base, stride, matched)
    return best


def main():
    sym = symbols()
    gd = game_dir()
    bins = {exe: (gd / exe).read_bytes() for exe in EXES}
    out = ["# 1oom struct-table sweep vs v1.3 EXEs", "",
           f"Generated by `tools/struct_sweep.py` on {datetime.date.today()} — 1oom @{ONEOOM_PIN}. "
           "Regenerate; don't hand-edit.", "",
           "Records are searched by their longest run of numeric fields (pointer/string fields dropped), "
           "as 16-bit words and as bytes. **LOCATED(window)** = found only by the sliding-window fallback (4 consecutive "
           "fields — 3 for short records — as int16, voted per field position): the original layout differs from 1oom's struct "
           "(inserted/reordered/narrower fields). "
           "as 16-bit words and as bytes. **LOCATED** = ≥3 records at one constant stride: the original "
           "table's offset and its real record size. Record indices not matched within a located table are "
           "where 1oom's values differ from v1.3 (or the record has too few numeric fields to search).", "",
           "| Verdict | 1oom table | records | Located in v1.3 | stride (B) | matched records | not matched |",
           "|---|---|---|---|---|---|---|"]
    summary = collections.Counter()
    for path, symbol in TABLES:
        line, n, best, any_hit, unresolved = sweep_table(path, symbol, sym, bins)
        if best and len(best[4]) >= 3:
            exe, w, base, stride, matched = best
            verdict = "LOCATED"
            miss = [i for i in range(n) if i not in matched]
            loc = f"{exe} {'int16' if w == 2 else 'int8'} @0x{base:X}"
            row = f"| {verdict} | `{path}:{line}` `{symbol}` | {n} | {loc} | {stride} | {len(matched)}/{n} | {miss[:20]}{' …' if len(miss) > 20 else ''} |"
        elif (wb := max(((exe,) + r for exe in bins
                          if (r := window_sweep([numeric_flat(x, sym) for x in table_records(path, symbol)], bins[exe]))),
                         key=lambda t: len(t[4]), default=None)):
            exe, j, base, stride, matched = wb
            verdict = "LOCATED(window)"
            miss = [i for i in range(n) if i not in matched]
            row = (f"| {verdict} | `{path}:{line}` `{symbol}` | {n} | {exe} int16, 1oom field #{j} "
                   f"@0x{base:X} | {stride} | {len(matched)}/{n} | {miss[:20]}{' …' if len(miss) > 20 else ''} |")
        elif any_hit:
            verdict = "PARTIAL"
            row = f"| {verdict} | `{path}:{line}` `{symbol}` | {n} | — | — | records {any_hit[:15]} hit somewhere | |"
        else:
            verdict = "ABSENT"
            row = f"| {verdict} | `{path}:{line}` `{symbol}` | {n} | — | — | 0/{n} | |"
        if unresolved:
            row += f" <!-- unresolved: {', '.join(unresolved[:6])} -->"
        summary[verdict] += 1
        out.append(row)
        print(row[:200])
    out[4:4] = [f"**{len(TABLES)} tables:** " + ", ".join(f"{k} {v}" for k, v in summary.items()), ""]
    (ROOT / "notes" / "struct-sweep.md").write_text("\n".join(out) + "\n", encoding="utf8")
    print(dict(summary))


if __name__ == "__main__":
    main()
