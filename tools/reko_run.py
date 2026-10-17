"""Run the Reko decompiler on a MOO1 EXE's root module, auto-skipping procedures that abort Reko's
global data-flow pass, and write a typed-C decompilation to work/reko/<EXE>/ (gitignored).

Why the skip loop: on STARMAP.EXE, Reko 0.12.5 aborts *global* analysis on a single procedure
("Boundless recursion in fnXXXX_YYYY while finding definitions of ss"), which leaves every procedure
untyped. Marking that procedure `decompile=false` lets the rest complete. Skipped procedures are
listed in work/reko/<EXE>/skipped.txt — they are exactly the ones to read by hand (tools/disasm.py).
Reko covers the ROOT module only: Borland FBOV overlays are not loaded (overlay splitter: TODO).
Reko's addresses: root loaded at segment 0800, so Reko seg:off = 0800 + image offset (dos_addr.py).
Trust Reko's control flow and constants; NOT its types (it writes 16-bit stores as `char`).

Config: `reko = '<path to decompile.exe>'` in config.toml.
Usage:  py -3 tools/reko_run.py STARMAP.EXE [--rounds 10]
"""
import argparse, re, shutil, subprocess, tomllib
from common import ROOT, game_dir

SEED_SKIP = {"STARMAP.EXE": ["fn37EE_00C3"]}   # structuring crash seen in the first run (2026-10-17)


def project(exe, skip):
    procs = "".join(f'      <procedure name="{p}">\n        <address>{p[2:6]}:{p[7:]}</address>\n'
                    f'        <decompile>false</decompile>\n      </procedure>\n' for p in skip)
    return f'''<?xml version="1.0" encoding="utf-8"?>
<project xmlns="http://schemata.jklnet.org/Reko/v5">
  <arch>x86-real-16</arch>
  <platform>ms-dos</platform>
  <input>
    <filename>{exe}</filename>
    <user>
{procs}    </user>
  </input>
</project>
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--rounds", type=int, default=10)
    a = ap.parse_args()
    reko = tomllib.loads((ROOT / "config.toml").read_text())["reko"]
    out = ROOT / "work" / "reko" / a.exe
    out.mkdir(parents=True, exist_ok=True)
    shutil.copy(game_dir() / a.exe, out / a.exe)
    skip = list(SEED_SKIP.get(a.exe, []))
    for rnd in range(a.rounds):
        (out / "project.dcproject").write_text(project(a.exe, skip), encoding="utf8")
        log = subprocess.run([reko, "project.dcproject"], cwd=out, capture_output=True,
                             text=True, errors="replace").stdout
        (out / "reko.log").write_text(log, encoding="utf8")
        m = re.search(r"internal error occurred while analyzing.*?\n\s*(.+?)\n", log, re.S)
        if not m:
            break
        p = re.search(r"\b(fn[0-9A-F]{4}_[0-9A-F]{4})\b", m.group(1))
        print(f"round {rnd}: global abort — {m.group(1).strip()[:100]}")
        if not p or p.group(1) in skip:
            raise SystemExit("cannot attribute the abort to a procedure; see reko.log")
        skip.append(p.group(1))
    else:
        raise SystemExit(f"still aborting after {a.rounds} rounds; skipped {skip}")
    (out / "skipped.txt").write_text("\n".join(skip) + "\n", encoding="utf8")
    c = next((out / "project.reko").glob("*.c"), None) or next(out.rglob("*.c"))
    heads = re.findall(r"^// [0-9A-F]{4}:[0-9A-F]{4}: (\S+)", c.read_text(errors="replace"), re.M)
    typed = sum(h != "define" for h in heads)
    runtime = re.search(r"^(.*runtime detected)$", log, re.M)
    print(f"{a.exe}: {len(heads)} procedures ({typed} typed), skipped {skip}; "
          f"{runtime.group(1) if runtime else 'no runtime id'}\n-> {c.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
