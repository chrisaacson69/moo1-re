"""Join DOSBox runtime addresses to EXE file offsets: MZ root module + Borland FBOV overlays.

The static<->runtime join that stalled zappatic's stream, solved by arithmetic, not a debugger UI.
Always work in LINEAR addresses (seg*16+off); a raw seg:off pair is not comparable across tools.

  ROOT module (file [header_size, image_end)): DOS loads the image at segment B = PSP + 0x10, so
      runtime linear = B*16 + (file_offset - header_size)
  and every relocation-table word holds (file word + B). Ghidra's MzLoader base 0x1000 is the
  special case B = 0x1000 (REA's DOS profile); not checked here, as Ghidra isn't installed.
  OVERLAYS (file >= image_end, after the 16-byte 'FBOV' header): each overlay segment has a stub
  in the root, `CD 3F 00 00 <u32 ovl_off> <u16 code_size> <u16 fixup_size> <u16 n_entries>`,
  listed in the segment table the FBOV header points to. VROOMM loads an overlay at <buffer
  seg>:0000, so a runtime offset inside a loaded overlay IS the offset into that overlay's code:
      file_offset = image_end + 16 + ovl_off + runtime_off
  Which overlay sits in the buffer is run-dependent: `live` finds out by byte match.

Usage:
  py -3 tools/dos_addr.py map STARMAP.EXE                  # header, root range, overlay table
  py -3 tools/dos_addr.py where STARMAP.EXE 0x6CE39        # root/overlay + in-module offset
  py -3 tools/dos_addr.py root STARMAP.EXE 0823 92FC     # root seg:off -> file, given load seg
  py -3 tools/dos_addr.py live [--pid N]                   # read a running DOSBox and VERIFY
`live` (Windows; reads the DOSBox process's memory read-only, stdlib ctypes) finds guest RAM by
its IVT, finds whichever EXE is resident, observes its PSP/MCB, and checks the formula against
every relocation site, every verified table in notes/table-sweep.md, and the resident overlays.
"""
import argparse, re, struct, sys
from common import ROOT, game_dir

EXES = ["ORION.EXE", "STARMAP.EXE"]


class Exe:
    def __init__(self, name):
        self.name = name
        d = self.data = (game_dir() / name).read_bytes()
        (cblp, cp, self.nrel, hpar, _mina, _maxa, self.ss, self.sp, _cs, self.ip, self.cs,
         lfarlc, _ovno) = struct.unpack_from("<13H", d, 2)
        self.hdr = hpar * 16
        self.end = (cp - 1) * 512 + (cblp or 512)            # end of the load module in the file
        self.image = d[self.hdr:self.end]
        self.relocs = [o + s * 16 for o, s in (struct.unpack_from("<HH", d, lfarlc + 4 * i)
                                               for i in range(self.nrel))]
        self.overlays = []
        if d[self.end:self.end + 4] == b"FBOV":
            _size, segtbl, nseg = struct.unpack_from("<III", d, self.end + 4)
            for i in range(nseg):
                seg, maxoff, flags, minoff = struct.unpack_from("<4H", d, segtbl + 8 * i)
                stub = self.hdr + seg * 16
                if flags & 2 and d[stub:stub + 2] == b"\xcd\x3f":   # flags 3 = overlaid code
                    off, csize, fsize, nent = struct.unpack_from("<IHHH", d, stub + 4)
                    self.overlays.append(dict(idx=i, stub_seg=seg, file=self.end + 16 + off,
                                              size=csize, fixups=fsize, entries=nent))

    def where(self, fo):
        if fo < self.hdr:
            return "MZ header"
        if fo < self.end:
            return f"root, image offset {fo - self.hdr:#x} (= Ghidra@1000 linear {0x10000 + fo - self.hdr:#x}, unverified)"
        for o in self.overlays:
            if o["file"] <= fo < o["file"] + o["size"]:
                return f"overlay #{o['idx']} (stub seg {o['stub_seg']:#06x}), runtime offset {fo - o['file']:#06x}"
        return "appended data outside any overlay's code (FBOV header or fixups)"


def cmd_map(a):
    e = Exe(a.exe)
    print(f"{e.name}: {len(e.data)} B; header {e.hdr:#x}; load module file [{e.hdr:#x}, {e.end:#x}) = "
          f"{e.end - e.hdr:#x} B; {e.nrel} relocations; entry {e.cs:04X}:{e.ip:04X}; stack {e.ss:04X}:{e.sp:04X}")
    print(f"appended after load module: {len(e.data) - e.end} B; FBOV overlays: {len(e.overlays)}")
    for o in e.overlays:
        print(f"  #{o['idx']:3} stub {o['stub_seg']:04X}  file [{o['file']:#08x},{o['file'] + o['size']:#08x})"
              f"  code {o['size']:#06x}  fixups {o['fixups']:#05x}  entries {o['entries']}")


def cmd_where(a):
    print(Exe(a.exe).where(int(a.offset, 16)))


def cmd_root(a):
    e, base, seg, off = Exe(a.exe), int(a.base, 16), int(a.seg, 16), int(a.off, 16)
    img = seg * 16 + off - base * 16
    if not 0 <= img < e.end - e.hdr:
        sys.exit(f"linear {seg * 16 + off:#x} is outside the root image at base {base:04X} "
                 f"(image offset {img:#x}); an overlay buffer or the heap?")
    print(f"{seg:04X}:{off:04X} -> image {img:#x} -> file {e.hdr + img:#x}: {e.data[e.hdr + img:e.hdr + img + 16].hex(' ')}")


# ---------------------------------------------------------------- live (Windows, read-only) ---
def _dosbox_memory(pid):
    """Yield (address, bytes) for every committed readable region of the DOSBox process."""
    import ctypes
    from ctypes import wintypes as w
    k = ctypes.WinDLL("kernel32", use_last_error=True)

    class MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", w.DWORD), ("PartitionId", w.WORD), ("RegionSize", ctypes.c_size_t),
                    ("State", w.DWORD), ("Protect", w.DWORD), ("Type", w.DWORD)]
    k.OpenProcess.restype = w.HANDLE
    k.VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
    k.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                    ctypes.POINTER(ctypes.c_size_t)]
    h = k.OpenProcess(0x0400 | 0x0010, False, pid)   # QUERY_INFORMATION | VM_READ — nothing else
    if not h:
        sys.exit(f"OpenProcess({pid}) failed: {ctypes.get_last_error()}")
    addr, m = 0, MBI()
    while k.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(m), ctypes.sizeof(m)):
        base, size = m.BaseAddress or 0, m.RegionSize
        if m.State == 0x1000 and not m.Protect & 0x101 and size < 1 << 28:   # COMMIT, not NOACCESS/GUARD
            buf, got = ctypes.create_string_buffer(size), ctypes.c_size_t()
            if k.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size, ctypes.byref(got)):
                yield base, buf.raw[:got.value]
        addr = base + size
        if addr >= 1 << 47:
            break
    k.CloseHandle(h)


def _find_pid():
    import subprocess, csv, io
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq DOSBox.exe", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True).stdout
    pids = [int(r[1]) for r in csv.reader(io.StringIO(out)) if len(r) > 1 and r[1].isdigit()]
    if len(pids) != 1:
        sys.exit(f"need exactly one running DOSBox.exe, found {pids}; pass --pid")
    return pids[0]


def _guest_ram(regions):
    """Conventional memory (1 MB) of the guest, located by machine structure, not by any game byte:
    the BIOS date string at F000:FFF5 (linear 0xFFFF5), confirmed by an IVT at linear 0 whose
    vectors mostly point into the F000 BIOS."""
    date = re.compile(rb"\d\d/\d\d/\d\d")
    for base, blob in regions:
        for m in date.finditer(blob):
            i = m.start() - 0xFFFF5
            if i < 0 or i + 0x100000 > len(blob):
                continue
            segs = [struct.unpack_from("<H", blob, i + 4 * v + 2)[0] for v in range(256)]
            if sum(s == 0xF000 for s in segs) >= 64:     # DOSBox 0.74: 96 F000, unused = 0:0
                return base + i, blob[i:i + 0x100000]
    sys.exit("no guest RAM found (BIOS date + IVT) — is the game running in this DOSBox?")


def _verified_tables():
    """(exe, file offset, byte length, label) for every FULL row of the generated table sweep."""
    rows = []
    for line in (ROOT / "notes" / "table-sweep.md").read_text(encoding="utf8").splitlines():
        if not line.startswith("| FULL"):
            continue
        cells = [c.strip() for c in line.split("|")]
        name, count = cells[2].split("`")[-2], int(cells[4])
        for m in re.finditer(r"(ORION|STARMAP)\.EXE (u?int(8|16)) @0x([0-9A-F]+)", cells[5]):
            rows.append((m[1] + ".EXE", int(m[4], 16), count * int(m[3]) // 8, name))
    return sorted(set(rows))


def cmd_live(a):
    pid = a.pid or _find_pid()
    ram_at, ram = _guest_ram(_dosbox_memory(pid))
    print(f"DOSBox pid {pid}: guest RAM (IVT) at host {ram_at:#x}")
    rd = lambda lin, n=2: ram[lin:lin + n]
    w16 = lambda lin: struct.unpack_from("<H", ram, lin)[0]
    # Candidate bases come from relocation-free, high-entropy 48-byte image windows (position-
    # independent). Stale fragments of the other EXE survive a chain-exec, so a window hit is only a
    # candidate: the resident image is the one whose RELOCATED words also read file word + B.
    cands = []
    for name in EXES:
        e = Exe(name)
        reloc_bytes = {r + k for r in e.relocs for k in (0, 1)}
        bases = set()
        for s in range(0x100, len(e.image) - 48, len(e.image) // 8):
            while s < len(e.image) - 48 and (len(set(e.image[s:s + 48])) < 28
                                              or any(x in reloc_bytes for x in range(s, s + 48))):
                s += 16
            if s >= len(e.image) - 48:
                continue
            bases |= {m.start() - s for m in re.finditer(re.escape(e.image[s:s + 48]), ram)
                      if (m.start() - s) % 16 == 0 and m.start() >= s}
        for lin in sorted(bases):
            ok = sum(w16(lin + r) == (struct.unpack_from("<H", e.image, r)[0] + lin // 16) & 0xFFFF
                     for r in e.relocs if lin + r + 2 <= len(ram))
            print(f"{name}: candidate base {lin // 16:04X}: {ok}/{len(e.relocs)} relocations agree")
            cands.append((ok / len(e.relocs), e, lin, reloc_bytes))
    if not cands or max(cands, key=lambda c: c[0])[0] < 0.5:
        sys.exit("no EXE root image with consistent relocations in conventional memory")
    _, e, lin, reloc_bytes = max(cands, key=lambda c: c[0])
    B = lin // 16
    print(f"\n== {e.name} resident: image base B = {B:04X} (observed, from bytes) ==")
    mcb, psp = (B - 0x11) * 16, (B - 0x10) * 16
    print(f"PSP {B - 0x10:04X}: starts {rd(psp).hex(' ')} (want cd 20); MCB {B - 0x11:04X}: type "
          f"{rd(mcb, 1)!r}, owner {w16(mcb + 1):04X} (want {B - 0x10:04X}) -> "
          f"{'PSP CONFIRMED' if rd(psp) == b'\xcd\x20' and w16(mcb + 1) == B - 0x10 else 'PSP MISMATCH'}")
    ok = sum(w16(lin + r) == (struct.unpack_from("<H", e.image, r)[0] + B) & 0xFFFF for r in e.relocs)
    print(f"relocations: {ok}/{len(e.relocs)} words == file word + B")
    print("verified tables at predicted linear = B*16 + (file_offset - header):")
    for exe, fo, n, label in _verified_tables():
        if exe != e.name:
            continue
        p = lin + fo - e.hdr
        print(f"  {'HIT ' if rd(p, n) == e.data[fo:fo + n] else 'MISS'} {label:34} file {fo:#07x} -> "
              f"{p // 16:04X}:{p % 16:04X} (linear {p:#07x})")
    dg = struct.unpack_from("<H", e.image, 1)[0] if e.image[0] == 0xBA else None   # Borland c0: mov dx,DGROUP
    code_end = dg * 16 if dg else len(e.image)
    diff = sum(ram[lin + i] != e.image[i] for i in range(code_end) if i not in reloc_bytes)
    print(f"code image [0,{code_end:#x}) (below DGROUP) byte diffs excluding relocations: {diff}")
    for o in e.overlays:
        code = e.data[o["file"]:o["file"] + o["size"]]
        for s in range(0, max(1, len(code) - 32), 16):
            if len(set(code[s:s + 32])) >= 16:
                break
        for m in re.finditer(re.escape(code[s:s + 32]), ram):
            st = m.start() - s
            same = sum(x == y for x, y in zip(ram[st:st + len(code)], code))
            if st % 16 == 0 and same > 0.9 * len(code):
                print(f"overlay #{o['idx']} (stub {o['stub_seg']:04X}) resident at {st // 16:04X}:0000, "
                      f"{same}/{len(code)} code bytes identical (rest = fixups/self-modified)")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("map"); p.add_argument("exe"); p.set_defaults(f=cmd_map)
    p = sub.add_parser("where"); p.add_argument("exe"); p.add_argument("offset"); p.set_defaults(f=cmd_where)
    p = sub.add_parser("root"); p.add_argument("exe"); p.add_argument("base"); p.add_argument("seg")
    p.add_argument("off"); p.set_defaults(f=cmd_root)
    p = sub.add_parser("live"); p.add_argument("--pid", type=int); p.set_defaults(f=cmd_live)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
