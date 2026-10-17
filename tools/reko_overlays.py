"""Decompile every Borland FBOV overlay of a MOO1 EXE with Reko, one overlay per run.

Why per overlay: Reko on the whole de-overlayed EXE (tools/deoverlay.py) aborts global data-flow
with an error it can't attribute to a procedure; per-overlay runs confine any crash to one overlay.
Each overlay is fed as a RAW blob loaded at its de-overlay segment (+ Reko's base 0800), with its
fixups applied for that same base, so calls into the root carry the SAME addresses Reko uses in the
root-only run (tools/reko_run.py) — e.g. the RNG is 0900:00DD in both. Stub entries become user
procedures `ovl<N>_<off>`.

Requires work/deoverlay/<EXE>.map.json (run tools/deoverlay.py first). Output: work/reko/overlays/
<EXE>/ovl<N>/, plus summary.json (procedures, typed, errors per overlay).
Usage:  py -3 tools/reko_overlays.py STARMAP.EXE [--only 71,74]
"""
import argparse, json, re, struct, subprocess, tomllib
from common import ROOT
import dos_addr, deoverlay

REKO_BASE = 0x0800


def project(name, seg, entries):
    procs = "".join(f'      <procedure name="{name}_{t:04X}">\n        <address>{seg:04X}:{t:04X}</address>\n'
                    f'      </procedure>\n' for t in entries)
    return f'''<?xml version="1.0" encoding="utf-8"?>
<project xmlns="http://schemata.jklnet.org/Reko/v5">
  <arch>x86-real-16</arch>
  <platform>ms-dos</platform>
  <input>
    <filename>{name}.bin</filename>
    <user>
      <address>{seg:04X}:0000</address>
      <loader>raw</loader>
      <processor name="x86-real-16" />
      <platform name="ms-dos" />
{procs}    </user>
  </input>
</project>
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--only", help="comma-separated overlay indices")
    a = ap.parse_args()
    reko = tomllib.loads((ROOT / "config.toml").read_text())["reko"]
    exe = dos_addr.Exe(a.exe)
    omap = {o["idx"]: o for o in json.loads((ROOT / "work" / "deoverlay" / f"{a.exe}.map.json").read_text())["overlays"]}
    only = {int(x) for x in a.only.split(",")} if a.only else None
    base = ROOT / "work" / "reko" / "overlays" / a.exe
    summary = {}
    for o in exe.overlays:
        if only and o["idx"] not in only:
            continue
        name = f"ovl{o['idx']}"
        out = base / name
        out.mkdir(parents=True, exist_ok=True)
        code, _ = deoverlay.fixed_overlay_code(exe, o, REKO_BASE)   # index x 8 -> image seg + Reko base
        (out / f"{name}.bin").write_bytes(code)
        seg = int(omap[o["idx"]]["new_seg"], 16) + REKO_BASE
        entries = [int(e["target"], 16) for e in omap[o["idx"]]["entries"]]
        (out / f"{name}.dcproject").write_text(project(name, seg, entries), encoding="utf8")
        log = subprocess.run([reko, f"{name}.dcproject"], cwd=out, capture_output=True,
                             text=True, errors="replace").stdout
        (out / "reko.log").write_text(log, encoding="utf8")
        cs = list(out.rglob("*.c"))
        heads = [h for c in cs for h in re.findall(r"^// [0-9A-F]{4}:[0-9A-F]{4}: (.+)$",
                                                   c.read_text(errors="replace"), re.M)]
        errors = len(re.findall(r": error: ", log))
        summary[o["idx"]] = dict(seg=f"{seg:04X}", entries=len(entries), procedures=len(heads),
                                 typed=sum(not h.startswith("define") for h in heads), errors=errors,
                                 global_abort="internal error occurred" in log)
        s = summary[o["idx"]]
        print(f"{name:6} seg {s['seg']}  entries {s['entries']:3}  procs {s['procedures']:4}  "
              f"typed {s['typed']:4}  errors {errors}{'  GLOBAL ABORT' if s['global_abort'] else ''}")
    (base / "summary.json").write_text(json.dumps(summary, indent=1))
    tot = lambda k: sum(v[k] for v in summary.values())
    print(f"total: {len(summary)} overlays, {tot('procedures')} procedures ({tot('typed')} typed), "
          f"{sum(v['global_abort'] for v in summary.values())} global aborts")


if __name__ == "__main__":
    main()
