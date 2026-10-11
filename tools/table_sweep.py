"""Sweep every hard-coded integer table in 1oom against the original v1.3 executables.

For each `const <int type> name[...] = {...}` in refs/1oom/src (>= MIN_VALUES literals, no strings):
  FULL     — whole table found byte-for-byte (offset + encoding reported)
  NEAR     — found anchored on its first or last ANCHOR values with a few entries different:
             the differing indices are listed (a 1oom change/fix, or a lookalike — inspect)
  AMBIG    — full match, but too short/low-entropy to be meaningful, or matched in many places
  ABSENT   — not found (NOT a refutation: data may be computed, packed, or live in an LBX)

Writes notes/table-sweep.md. Usage: py -3 tools/table_sweep.py
"""
import re, pathlib, datetime
from common import ONEOOM, ONEOOM_PIN, ROOT, game_dir
from exe_find import EXES, encode

MIN_VALUES, ANCHOR, MAX_DIFF_FRAC, MIN_BYTES = 6, 6, 0.25, 12
INT_TYPES = {"uint8_t", "int8_t", "uint16_t", "int16_t", "int", "uint32_t", "int32_t",
             "unsigned int", "short", "unsigned short", "unsigned char", "signed char"}
DECL = re.compile(r"(?:static\s+)?const\s+([A-Za-z_][\w ]*?)\s+\*?\s*([A-Za-z_]\w*)\s*((?:\[[^\]]*\])+)\s*=\s*\{")
NUM = re.compile(r'(?<![\w"])-?(?:0x[0-9a-fA-F]+|\d+)(?![\w"])')


def tables():
    for f in sorted((ONEOOM / "src").rglob("*.c")):
        s = f.read_text(encoding="latin1")
        for m in DECL.finditer(s):
            ctype, name = m.group(1).strip(), m.group(2)
            if ctype not in INT_TYPES:
                continue
            i, depth = m.end() - 1, 0
            for j in range(i, len(s)):
                depth += {"{": 1, "}": -1}.get(s[j], 0)
                if depth == 0:
                    break
            body = re.sub(r"/\*.*?\*/|//[^\n]*", "", s[i:j + 1], flags=re.S)
            vals = [int(t, 0) for t in NUM.findall(body)]
            if '"' in body or len(vals) < MIN_VALUES:
                continue
            line = s.count("\n", 0, m.start()) + 1
            yield f.relative_to(ONEOOM).as_posix(), line, name, ctype, vals


def encodings(ctype, vals):
    """Widths worth trying: the declared width first, then the other (a C int may be 8/16 in the EXE)."""
    order = ["int8", "uint8", "int16", "uint16"]
    if "16" in ctype or ctype in ("int", "short", "unsigned short", "unsigned int"):
        order = ["int16", "uint16", "int8", "uint8"]
    return [(e, p) for e in order if (p := encode(vals, e)) is not None]


def find_all(data, pat):
    out, k = [], data.find(pat)
    while k >= 0:
        out.append(k)
        k = data.find(pat, k + 1)
    return out


def classify(vals, bins):
    width = lambda e: 1 if "8" in e else 2
    full, near = [], []
    for exe, data in bins.items():
        for enc, pat in encodings(*vals):
            hits = find_all(data, pat)
            full += [(exe, enc, h) for h in hits]
            if hits:
                continue
            w, n = width(enc), len(vals[1])
            for anchor_at_end in (False, True):
                a = pat[-ANCHOR * w:] if anchor_at_end else pat[:ANCHOR * w]
                for h in find_all(data, a)[:50]:
                    start = h - (len(pat) - ANCHOR * w) if anchor_at_end else h
                    if start < 0 or start + len(pat) > len(data):
                        continue
                    region = data[start:start + len(pat)]
                    diff = [k for k in range(n) if region[k * w:(k + 1) * w] != pat[k * w:(k + 1) * w]]
                    if 0 < len(diff) <= MAX_DIFF_FRAC * n:
                        got = [int.from_bytes(region[k * w:(k + 1) * w], "little", signed=enc.startswith("int"))
                               for k in diff]
                        near.append((exe, enc, start, diff, got))
    return full, near


def main():
    gd = game_dir()
    bins = {exe: (gd / exe).read_bytes() for exe in EXES}
    rows, counts = [], {}
    for path, line, name, ctype, vals in tables():
        full, near = classify((ctype, vals), bins)
        nbytes = len(vals) * (2 if "16" in ctype or ctype == "int" else 1)
        distinct = len(set(vals))
        if full:
            weak = nbytes < MIN_BYTES or distinct <= 2 or len({(e, h) for e, _, h in full}) > 3
            verdict = "AMBIG" if weak else "FULL"
            where = "; ".join(f"{e} {enc} @0x{h:X}" for e, enc, h in full[:3]) + (" …" if len(full) > 3 else "")
        elif near:
            near.sort(key=lambda r: len(r[3]))
            e, enc, h, diff, got = near[0]
            verdict = "NEAR"
            where = (f"{e} {enc} @0x{h:X}; differs at idx {diff[:8]}{'…' if len(diff) > 8 else ''}: "
                     f"1oom {[vals[k] for k in diff[:8]]} vs EXE {got[:8]}")
        else:
            verdict, where = "ABSENT", ""
        counts[verdict] = counts.get(verdict, 0) + 1
        rows.append((verdict, path, line, name, ctype, len(vals), where))
    order = {"FULL": 0, "NEAR": 1, "AMBIG": 2, "ABSENT": 3}
    rows.sort(key=lambda r: (order[r[0]], r[1], r[2]))
    out = [f"# 1oom table sweep vs v1.3 EXEs",
           f"",
           f"Generated by `tools/table_sweep.py` on {datetime.date.today()} — 1oom @{ONEOOM_PIN}, "
           f"Steam v1.3 `ORION.EXE` + `STARMAP.EXE`. Regenerate; don't hand-edit.",
           f"",
           f"**{sum(counts.values())} integer tables** (≥{MIN_VALUES} values): " +
           ", ".join(f"{k} {counts.get(k, 0)}" for k in order),
           f"",
           f"ABSENT is not a refutation (computed, packed, or LBX data). NEAR = inspect: a 1oom change, "
           f"a v1.3 variant, or a lookalike. AMBIG = matched, but too short/repetitive to count as evidence.",
           f"",
           f"| Verdict | 1oom table | Type | n | Where in v1.3 |",
           f"|---|---|---|---|---|"]
    out += [f"| {v} | `{p}:{l}` `{n}` | {t} | {k} | {w} |" for v, p, l, n, t, k, w in rows]
    (ROOT / "notes").mkdir(exist_ok=True)
    (ROOT / "notes" / "table-sweep.md").write_text("\n".join(out) + "\n", encoding="utf8")
    print(counts)


if __name__ == "__main__":
    main()
