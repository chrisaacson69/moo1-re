"""Module map: divide STARMAP into its compile units and layer them bottom-up.

Borland's large model gives each .C file (and each library module) its own code segment, and the
FBOV header's segment table lists every segment the linker emitted: base, size and flags
(1 = root code, 3 = overlaid code, 4 = data, 0 = other). That is an unnamed equivalent of the SNES's
named segments — module boundaries straight from the linker. This tool:

  * assigns every Reko procedure to its module (root: Reko seg - 0x0800 = image seg; overlays: ovlN)
  * builds the module call graph (from Reko's C), condenses cycles, and LAYERS it bottom-up:
    level 0 = calls no other module; level n = 1 + highest level it calls
  * fingerprints each module from its raw bytes: INT 21h (DOS), 10h (video BIOS), 33h (mouse),
    16h (keyboard), 3Fh (overlay manager), port I/O (in/out), VGA ports 3C4/3CE/3D4, video
    segment A000 — plus how many DGROUP strings it references and which 1oom source files its paired
    procedures (work/coverage/<EXE>.json) point to
  * proposes a CLASS per module: HW/RTL (bytes touch hardware/DOS directly), GAME / UI (1oom pairs
    dominated by src/game or src/ui), or ? — a proposal for review, not a verdict

Bottom-up is the point: name the low layers once (they are called from everywhere), and every module
above them reads better. Writes notes/module-map.md (generated) and work/modules/<EXE>.json.
Usage:  py -3 tools/module_map.py STARMAP.EXE      (after reko_run, reko_overlays, coverage_map)
"""
import argparse, collections, json, re, struct
from common import ROOT
import dos_addr, coverage_map

REKO_BASE = 0x0800
INTS = {0x21: "dos", 0x10: "video", 0x33: "mouse", 0x16: "kbd", 0x3F: "ovlmgr", 0x1A: "time"}


def modules(exe):
    e = dos_addr.Exe(exe)
    _s, segtbl, nseg = struct.unpack_from("<III", e.data, e.end + 4)
    mods, ovl_by_seg = [], {o["stub_seg"]: o for o in e.overlays}
    for i in range(nseg):
        seg, maxoff, flags, minoff = struct.unpack_from("<4H", e.data, segtbl + 8 * i)
        if flags == 1:
            lo = e.hdr + seg * 16
            mods.append(dict(id=f"seg{seg:04X}", kind="root", seg=seg, size=maxoff, bytes=e.data[lo:lo + maxoff]))
        elif flags == 3 and seg in ovl_by_seg:
            o = ovl_by_seg[seg]
            mods.append(dict(id=f"ovl{o['idx']}", kind="overlay", seg=seg, size=o["size"],
                             bytes=e.data[o["file"]:o["file"] + o["size"]]))
    return mods


def fingerprint(code):
    """Hardware/DOS use, from decoded instructions (Capstone linear sweep; counts, not exact)."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.skipdata = True
    f = collections.Counter()
    for ins in md.disasm(code, 0):
        m = ins.mnemonic
        if m == "int":
            try:
                n = int(ins.op_str, 16)
            except ValueError:
                continue
            if n in INTS:
                f["int_" + INTS[n]] += 1
        elif m in ("in", "out", "insb", "insw", "outsb", "outsw"):
            f["port_io"] += 1
        elif m == "mov" and ins.op_str.startswith("dx, "):
            port = ins.op_str[4:]
            name = {"0x3c4": "vga_seq", "0x3ce": "vga_gc", "0x3d4": "vga_crtc", "0x3c8": "vga_dac"}.get(port)
            if name:
                f[name] += 1
        if "0xa000" in ins.op_str:
            f["a000"] += 1
    return {k: v for k, v in f.items() if v}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    a = ap.parse_args()
    mods = modules(a.exe)
    B = coverage_map.binary_procs(a.exe)
    pairs = {r["proc"]: r for r in json.loads((ROOT / "work" / "coverage" / f"{a.exe}.json").read_text())}
    md = (ROOT / "notes" / "coverage-map.md").read_text(encoding="utf8")
    file_of = {m.group(1): m.group(2) for m in re.finditer(r"`(\w+)` \((src/[\w/]+\.c):\d+\)", md)}
    roots = sorted((m for m in mods if m["kind"] == "root"), key=lambda m: m["seg"])

    def mod_of(proc):
        if proc.startswith("ovl"):
            return proc.split("_")[0]
        addr = B[proc]["addr"] if proc in B else proc[2:6] + ":" + proc[7:]
        if B.get(proc, {}).get("region", "root") != "root":
            return B[proc]["region"]
        s = int(addr[:4], 16) - REKO_BASE
        cand = [m for m in roots if m["seg"] <= s]
        return cand[-1]["id"] if cand else None
    byid = {m["id"]: dict(m, procs=[], calls=collections.Counter(), callers=collections.Counter(),
                          files=collections.Counter(), strings=0, paired=0) for m in mods}
    for p, v in B.items():
        mid = mod_of(p)
        if mid not in byid:
            continue
        M = byid[mid]
        M["procs"].append(p)
        M["strings"] += sum(isinstance(k, tuple) for k in v["consts"])
        r = pairs.get(p)
        if r and r["tier"] in ("CONFIDENT", "PROPAGATED", "WEAK") and r["best"] in file_of:
            M["files"][file_of[r["best"]].split("/")[1] + "/" + file_of[r["best"]].split("/")[-1]] += \
                2 if r["tier"] != "WEAK" else 1                           # weak pairs count half
            M["paired"] += r["tier"] != "WEAK"
        for q in v["calls"]:
            mq = mod_of(q)
            if mq and mq != mid and mq in byid:
                M["calls"][mq] += 1
                byid[mq]["callers"][mid] += 1
    # condense cycles (Tarjan), then level = 1 + max(level of callees)
    index, low, stack, onst, comp, cnt = {}, {}, [], set(), {}, [0]

    def strong(v):
        index[v] = low[v] = cnt[0]; cnt[0] += 1; stack.append(v); onst.add(v)
        for w in byid[v]["calls"]:
            if w not in index:
                strong(w); low[v] = min(low[v], low[w])
            elif w in onst:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            while True:
                w = stack.pop(); onst.discard(w); comp[w] = v
                if w == v:
                    break
    import sys
    sys.setrecursionlimit(10000)
    for v in byid:
        if v not in index:
            strong(v)
    level = {}

    def lvl(c):
        if c in level:
            return level[c]
        level[c] = 0
        members = [m for m in byid if comp[m] == c]
        callee = {comp[w] for m in members for w in byid[m]["calls"]} - {c}
        level[c] = 1 + max((lvl(x) for x in callee), default=-1)
        return level[c]
    for M in byid.values():
        M["fp"] = fingerprint(M["bytes"])
        M["level"] = lvl(comp[M["id"]])
        M["cycle"] = sum(comp[x] == comp[M["id"]] for x in byid) > 1
        game = sum(k for f, k in M["files"].items() if f.startswith("game/"))
        ui = sum(k for f, k in M["files"].items() if f.startswith("ui/"))
        hw = any(k in M["fp"] for k in ("int_dos", "int_video", "int_mouse", "int_kbd", "vga_seq", "vga_gc", "vga_crtc", "vga_dac"))
        first_stub = min((m["seg"] for m in mods if m["kind"] == "overlay"), default=1 << 20)
        M["class"] = ("OVL-STUBS" if M["kind"] == "root" and M["seg"] >= first_stub else
                      "LIB/HW" if hw and M["level"] == 0 else          # hardware-touching leaf = library
                      "LIB/HW" if hw and M["level"] <= 1 and game + ui < 6 else
                      "GAME" if game >= 2 * max(ui, 1) else "UI" if ui >= 2 * max(game, 1) else
                      "MIXED" if game + ui else "?")
    rows = sorted(byid.values(), key=lambda M: (M["level"], M["kind"], M["seg"]))
    (ROOT / "work" / "modules").mkdir(parents=True, exist_ok=True)
    (ROOT / "work" / "modules" / f"{a.exe}.json").write_text(json.dumps(
        [{k: (dict(v) if isinstance(v, collections.Counter) else v) for k, v in M.items() if k != "bytes"} for M in rows], indent=1))
    cls = collections.Counter(M["class"] for M in rows)
    bycls = collections.defaultdict(lambda: [0, 0])
    for M in rows:
        bycls[M["class"]][0] += len(M["procs"]); bycls[M["class"]][1] += M["paired"]
    out = [f"# Module map — {a.exe}", "",
           "Generated by `tools/module_map.py`; regenerate, don't hand-edit. Modules = the linker's code segments "
           "(FBOV segment table). Level 0 = calls no other module; bottom-up = read low levels first. CLASS is a proposal.", "",
           f"- **{len(rows)} code modules** ({sum(M['kind'] == 'root' for M in rows)} root, "
           f"{sum(M['kind'] == 'overlay' for M in rows)} overlay), {sum(len(M['procs']) for M in rows)} procedures; "
           f"levels 0–{max(M['level'] for M in rows)}; classes: " + ", ".join(f"{k} {v}" for k, v in cls.most_common()), "",
           "| Class | Modules | Procedures | Paired (confident+propagated) | Share |", "|---|---|---|---|---|"] +           [f"| {c} | {cls[c]} | {p} | {q} | {100 * q / max(p, 1):.0f}% |" for c, (p, q) in sorted(bycls.items(), key=lambda x: -x[1][0])] +           ["", "| Lvl | Module | Size | Procs | Paired | Callers (mods) | Calls (mods) | Strings | Hardware/DOS fingerprint | Top 1oom files | Class |",
           "|---|---|---|---|---|---|---|---|---|---|---|"]
    for M in rows:
        top = ", ".join(f"{f}×{k}" for f, k in M["files"].most_common(2))
        out.append(f"| {M['level']}{'*' if M['cycle'] else ''} | `{M['id']}` | {M['size']:#x} | {len(M['procs'])} | {M['paired']} | "
                   f"{len(M['callers'])} | {len(M['calls'])} | {M['strings']} | {', '.join(f'{k}:{v}' for k, v in M['fp'].items())} | {top} | {M['class']} |")
    out += ["", "`*` = module is in a call cycle with others (condensed for layering)."]
    (ROOT / "notes" / "module-map.md").write_text("\n".join(out) + "\n", encoding="utf8")
    print(f"{len(rows)} modules, levels 0–{max(M['level'] for M in rows)}; classes {dict(cls)}")


if __name__ == "__main__":
    main()
