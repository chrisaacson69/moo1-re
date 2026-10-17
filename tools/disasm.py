"""Disassemble STARMAP/ORION code by module-relative offset (root image or FBOV overlay) with Capstone.

Addresses are the ones dos_addr.py speaks: root = image offset; overlay N = runtime offset inside
overlay N (it loads at <buffer seg>:0000). Data-segment constants for STARMAP (derived 2026-10-17 by
voting verified tables against code memory operands — see notes/dos-address-join.md):
  DGROUP image seg 0x326B; players array DS:0x786E (stride 0xDD4; race +0, trait1 +4, trait2 +6).

Usage:
  py -3 tools/disasm.py STARMAP.EXE 74 0x04d2 60          # overlay 74, around offset 0x4d2, 60 insns
  py -3 tools/disasm.py STARMAP.EXE root 0x4896 40
  py -3 tools/disasm.py STARMAP.EXE 74 --grep 0x7874      # every instruction whose operands mention it
"""
import argparse, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_16
import dos_addr

MD = Cs(CS_ARCH_X86, CS_MODE_16)


def region(exe, which):
    if which == "root":
        return exe.hdr, exe.end
    o = next(o for o in exe.overlays if o["idx"] == int(which))
    return o["file"], o["file"] + o["size"]


def insns(exe, which, start=0, count=None):
    base, end = region(exe, which)
    return MD.disasm(exe.data[base + start:end], start, count=count or 0)


def around(exe, which, at, n, back=0x30):
    """Instructions from just before `at`, resynchronised so one instruction starts exactly at `at`."""
    for s in range(max(0, at - back), at + 1):
        out = list(insns(exe, which, s, n + 64))
        if any(i.address == at for i in out):
            return out[:n + 64]
    return list(insns(exe, which, at, n))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe"); ap.add_argument("region")
    ap.add_argument("at", nargs="?", type=lambda s: int(s, 0), default=0)
    ap.add_argument("n", nargs="?", type=int, default=40)
    ap.add_argument("--grep")
    a = ap.parse_args()
    exe = dos_addr.Exe(a.exe)
    if a.grep:
        for i in insns(exe, a.region):
            if re.search(re.escape(a.grep.lower()) + r"\b", i.op_str):
                print(f"{i.address:04x}  {i.mnemonic:6} {i.op_str}")
        return
    shown = 0
    for i in around(exe, a.region, a.at, a.n):
        if i.address >= a.at - 0x30:
            print(f"{'>' if i.address == a.at else ' '}{i.address:04x}  {i.mnemonic:6} {i.op_str}")
            shown += 1
            if shown >= a.n:
                break


if __name__ == "__main__":
    main()
