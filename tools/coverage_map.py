"""Coverage map: pair every decompiled v1.3 procedure (Reko) with its 1oom function.

Two independent signals, then propagation:
 1. CONSTANTS — each side a bag of integer literals: the binary's from Reko's C (root + overlays),
    1oom's from source with enums/#defines resolved (struct_sweep.symbols).
 2. DATA FIELDS — 1oom's `->field` accesses translated to the numbers the binary actually uses, from
    1oom's own save loader (game_save_moo13.c: planet `pb + off`, empire `eb + off`; RAM layout = save
    layout): a planet field adds its offset (`p->owner` -> 0x36); an empire field adds its absolute
    DS address in STARMAP (players at DS:0x786E: `e->treaty` -> 0x7946).
 Bags are restricted to the SHARED vocabulary (constants seen on both sides) and IDF-weighted; score =
 cosine. CONFIDENT = score >= MIN_SCORE and >= MARGIN x runner-up; WEAK = score only.
 3. CALL GRAPH — for each confident pair (b, f), b's unmatched callees are matched among f's callees
    (PROPAGATED, if the best clears PROP_MIN and the margin); iterated to a fixed point.

A **proposal** layer: pairs say where to compare, not that 1oom is right. ANCHORS verified by hand must
come out right, or the run says so.
Inputs: work/reko/<EXE>/ and work/reko/overlays/<EXE>/. Writes notes/coverage-map.md (generated) and
work/coverage/<EXE>.json.   Usage:  py -3 tools/coverage_map.py STARMAP.EXE
"""
import argparse, collections, json, math, random, re
from common import ONEOOM, ONEOOM_PIN, ROOT
import struct_sweep

MIN_SCORE, MARGIN, PROP_MIN = 0.30, 1.5, 0.10
MIN_SHARED, CONF_SHARED = 2, 3                      # distinct shared constants: to compete / to be CONFIDENT
# 1oom array indexing -> the record stride compiled v1.3 code multiplies by (save/RAM layout sizes)
STRIDES = {r"->\s*planet\s*\[": 0xB8, r"->\s*eto\s*\[": 0xDD4, r"->\s*enroute\s*\[": 0x1C,
           r"->\s*transport\s*\[": 0x12, r"->\s*srd\s*\[": 0x468}
IGNORE = set(range(0, 3))                           # 0/1/2 carry no identity
PLAYERS_DS = {"STARMAP.EXE": 0x786E}                # derived 2026-10-17 (notes/ai-slider-weights.md)
ANCHORS = {"fn1B75_000B": "game_ai_classic_turn_p3",   # disassembly, notes/ai-slider-weights.md
           "ovl71_1626": "game_send_fleet_do"}           # 260-cap check (0x104) + 1oom game_fleet.c:64
SRC_DIRS = ["src/game", "src/ui/classic"]
NUM = re.compile(r"(?<![\w.])(0x[0-9A-Fa-f]+|\d+)(?![\w.])")


def num(t):
    return int(t, 16) if t[:2] in ("0x", "0X") else int(t, 10)


def field_map(players_ds):
    """1oom field name -> set of binary-visible numbers, from the v1.3 save loader."""
    s = (ONEOOM / "src/game/game_save_moo13.c").read_text(encoding="latin1")
    fm = collections.defaultdict(set)
    for m in re.finditer(r"M13_GET\w*\(\s*(p|e)->(\w+)[^,]*,\s*(pb|eb)\s*\+\s*(0x[0-9a-fA-F]+|\d+)", s):
        off = num(m.group(4))
        fm[m.group(2)].add(off if m.group(1) == "p" else players_ds + off)
    return fm


def lits(text, sym=None, fields=None):
    out = collections.Counter()
    for m in NUM.finditer(text):
        v = num(m.group(1))
        if v not in IGNORE and v < 0x10000:
            out[v] += 1
    if sym:
        for name in re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", text):
            v = sym.get(name)
            if isinstance(v, int) and v not in IGNORE and 0 <= v < 0x10000:
                out[v] += 1
    if fields:
        for name in re.findall(r"->\s*(\w+)", text):
            for v in fields.get(name, ()):
                out[v] += 1
        for rx, stride in STRIDES.items():
            k = len(re.findall(rx, text))
            if k:
                out[stride] += k
    return out


def binary_procs(exe):
    procs = {}
    files = list((ROOT / "work" / "reko" / exe).rglob("*.c")) + \
        list((ROOT / "work" / "reko" / "overlays" / exe).rglob("*.c"))
    for f in files:
        text = f.read_text(errors="replace")
        heads = list(re.finditer(r"^// ([0-9A-F]{4}:[0-9A-F]{4}): (.*)$", text, re.M))
        for k, h in enumerate(heads):
            body = text[h.end():heads[k + 1].start() if k + 1 < len(heads) else len(text)]
            name = re.search(r"\b((?:fn|ovl\d+_)[0-9A-F_]+)\(", h.group(2))
            name = name.group(1) if name else h.group(1)
            body = re.sub(r"^//.*$", "", body, flags=re.M)
            calls = set(re.findall(r"\b((?:fn[0-9A-F]{4}_[0-9A-F]{4})|ovl\d+_[0-9A-F]{4})\(", body)) - {name}
            region = f.parent.parent.name if "overlays" in f.parts else "root"
            procs[name] = dict(addr=h.group(1), region=region, consts=lits(body), calls=calls)
    return procs


def oneoom_funcs(sym, fields):
    funcs = {}
    fdef = re.compile(r"^(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{", re.M)
    for d in SRC_DIRS:
        for f in sorted((ONEOOM / d).glob("*.c")):
            s = struct_sweep.strip_comments(f.read_text(encoding="latin1"))
            for m in fdef.finditer(s):
                if m.group(1) in ("if", "for", "while", "switch", "return"):
                    continue
                i, depth = m.end() - 1, 0
                for j in range(i, len(s)):
                    depth += {"{": 1, "}": -1}.get(s[j], 0)
                    if depth == 0:
                        break
                body = s[i:j + 1]
                funcs[m.group(1)] = dict(file=f"{d}/{f.name}:{s.count(chr(10), 0, m.start()) + 1}",
                                         consts=lits(body, sym, fields), body=body)
    names = set(funcs)
    for v in funcs.values():
        v["calls"] = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", v.pop("body"))) & names
    return funcs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    a = ap.parse_args()
    sym, fields = struct_sweep.symbols(), field_map(PLAYERS_DS[a.exe])
    B, F = binary_procs(a.exe), oneoom_funcs(sym, fields)
    shared = set().union(*(v["consts"] for v in B.values())) & set().union(*(v["consts"] for v in F.values()))
    for side in (B, F):
        for v in side.values():
            v["consts"] = collections.Counter({k: x for k, x in v["consts"].items() if k in shared})
    df = collections.Counter()
    for side in (B, F):
        for v in side.values():
            df.update(set(v["consts"]))
    n = len(B) + len(F)
    idf = {c: math.log(n / k) for c, k in df.items()}

    def vec(c):
        w = {k: (1 + math.log(x)) * idf[k] for k, x in c.items()}
        norm = math.sqrt(sum(x * x for x in w.values())) or 1.0
        return {k: x / norm for k, x in w.items()}
    VB, VF = {k: vec(v["consts"]) for k, v in B.items()}, {k: vec(v["consts"]) for k, v in F.items()}
    inv = collections.defaultdict(list)
    for fn, v in VF.items():
        for c in v:
            inv[c].append(fn)

    def scored(bp, among=None):
        sc, nsh = collections.Counter(), collections.Counter()
        for c, wb in VB[bp].items():
            for fn in inv.get(c, ()):
                if among is None or fn in among:
                    sc[fn] += wb * VF[fn][c]; nsh[fn] += 1
        sc = collections.Counter({f: v for f, v in sc.items() if nsh[f] >= MIN_SHARED})  # no one-constant wins
        top = sc.most_common(2) + [(None, 0.0)] * 2
        return top[0], top[1], nsh.get(top[0][0], 0)

    res = {}
    for bp in B:
        (f1, s1), (f2, s2), k = scored(bp)
        tier = ("CONFIDENT" if s1 >= MIN_SCORE and s1 >= MARGIN * max(s2, 1e-9) and k >= CONF_SHARED else
                "WEAK" if s1 >= MIN_SCORE else "UNMATCHED")
        res[bp] = dict(best=f1, score=s1, second=f2, score2=s2, tier=tier, via="constants")
    changed = True
    while changed:                                  # call-graph propagation to a fixed point
        changed = False
        taken = {r["best"] for r in res.values() if r["tier"] in ("CONFIDENT", "PROPAGATED")}
        for bp, r in list(res.items()):
            if r["tier"] not in ("CONFIDENT", "PROPAGATED"):
                continue
            pool = F[r["best"]]["calls"] - taken
            for q in sorted(B[bp]["calls"]):
                if q not in res or res[q]["tier"] in ("CONFIDENT", "PROPAGATED") or not pool:
                    continue
                (f1, s1), (f2, s2), _ = scored(q, pool)
                if f1 and s1 >= PROP_MIN and s1 >= MARGIN * max(s2, 1e-9):
                    res[q] = dict(best=f1, score=s1, second=f2, score2=s2, tier="PROPAGATED", via=f"callee of {bp}")
                    taken.add(f1); pool.discard(f1); changed = True
    rows = [dict(proc=bp, addr=B[bp]["addr"], region=B[bp]["region"], **{k: (round(v, 3) if isinstance(v, float) else v)
                                                                       for k, v in r.items()}) for bp, r in res.items()]
    rows.sort(key=lambda r: (r["region"] != "root", r["region"], r["addr"]))
    anchors = {bp: (res.get(bp, {}).get("best") == fn, res.get(bp, {}).get("tier")) for bp, fn in ANCHORS.items()}
    tiers = collections.Counter(r["tier"] for r in rows)
    paired = collections.Counter(r["best"] for r in rows if r["tier"] in ("CONFIDENT", "PROPAGATED"))
    dup = {f: k for f, k in paired.items() if k > 1}
    game_funcs = [f for f, v in F.items() if v["file"].startswith("src/game")]
    unclaimed = sorted(f for f in game_funcs if f not in paired and len(F[f]["consts"]) >= 3)
    (ROOT / "work" / "coverage").mkdir(parents=True, exist_ok=True)
    (ROOT / "work" / "coverage" / f"{a.exe}.json").write_text(json.dumps(rows, indent=1))
    good = tiers["CONFIDENT"] + tiers["PROPAGATED"]
    # precision proxy: overlays are compile units, so real pairs inside one overlay cluster in few 1oom files
    def coh(pairs):
        per = collections.defaultdict(collections.Counter)
        for reg, f in pairs:
            per[reg][F[f]["file"].split(":")[0]] += 1
        m = [c for c in per.values() if sum(c.values()) >= 3]
        return sum(c.most_common(1)[0][1] / sum(c.values()) for c in m) / max(len(m), 1), len(m)
    pairs = [(r["region"], r["best"]) for r in rows if r["tier"] in ("CONFIDENT", "PROPAGATED") and r["region"] != "root"]
    coherence, nmulti = coh(pairs)
    rng, base = random.Random(1), []
    for _ in range(500):                            # permutation baseline: same overlays, shuffled 1oom targets
        tg = [f for _, f in pairs]; rng.shuffle(tg)
        base.append(coh(list(zip((g for g, _ in pairs), tg)))[0])
    base.sort()
    out = [f"# Coverage map — {a.exe} (v1.3) ↔ 1oom @{ONEOOM_PIN}", "",
           "Generated by `tools/coverage_map.py`; regenerate, don't hand-edit. A **proposal** layer: pairs "
           "say where to compare, not that 1oom is right.", "",
           f"- Binary procedures: **{len(B)}** (Reko root + overlays). 1oom functions: {len(F)} ({len(game_funcs)} in `src/game`).",
           f"- **Paired {good}/{len(B)} ({100 * good / len(B):.0f}%)**: CONFIDENT {tiers['CONFIDENT']} + PROPAGATED "
           f"{tiers['PROPAGATED']}; WEAK {tiers['WEAK']}; UNMATCHED {tiers['UNMATCHED']}.",
           f"- **Precision proxy — overlay coherence {coherence:.2f}**: mean share of an overlay's pairs that fall in its "
           f"single most common 1oom source file ({nmulti} overlays with ≥3 pairs) vs **{sum(base) / len(base):.2f}** for "
           f"500 shuffles of the same pairs (max {base[-1]:.2f}).",
           f"- Anchors: " + ", ".join(f"`{bp}`→`{ANCHORS[bp]}` {'✔' if ok else '✘'} ({t})" for bp, (ok, t) in anchors.items()),
           f"- 1oom functions claimed by >1 binary procedure (inspect — duplicates mean at least one is wrong): {len(dup)}",
           f"- 1oom `src/game` functions with ≥3 shared constants and no paired binary procedure: {len(unclaimed)}",
           "", "| Region | Proc | Addr | Tier | 1oom match | score | runner-up | score | via |", "|---|---|---|---|---|---|---|---|---|"]
    out += [f"| {r['region']} | `{r['proc']}` | {r['addr']} | {r['tier']} | `{r['best']}` "
            f"{'(' + F[r['best']]['file'] + ')' if r['best'] else ''} | {r['score']} | `{r['second']}` | {r['score2']} | {r['via']} |"
            for r in rows]
    out += ["", "## 1oom functions claimed more than once", "", ", ".join(f"`{f}`×{k}" for f, k in sorted(dup.items())),
            "", "## 1oom `src/game` functions without a paired binary procedure", "", ", ".join(f"`{f}`" for f in unclaimed)]
    (ROOT / "notes" / "coverage-map.md").write_text("\n".join(out) + "\n", encoding="utf8")
    print(dict(tiers), f"paired {good}/{len(B)}", "anchors:", anchors, "dups:", len(dup), "unclaimed:", len(unclaimed), f"coherence {coherence:.2f}")


if __name__ == "__main__":
    main()
