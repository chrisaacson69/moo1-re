"""De-overlay a Borland VROOMM (FBOV) MZ executable into one statically linked MZ for static analysis.

Decompilers (Reko, Ghidra) load only the root module of an FBOV program — half of STARMAP.EXE is
invisible to them. This rewrites the EXE so every overlay is resident at a fixed segment:

  * each overlay's code is placed, paragraph-aligned, ABOVE the root's DGROUP span (so overlay code
    never aliases data addresses: STARMAP's DGROUP runs to image linear 0x426AF, past the image end)
  * each overlay's fixup block (u16 offsets of words holding a segment-table INDEX x 8 — not an image
    segment; see fixed_overlay_code) is translated through the FBOV segment table and becomes MZ
    relocations — the loader then adds the load segment, as VROOMM would
  * each stub entry `CD 3F <u16 off> 00` (INT 3Fh = "load overlay and jump") becomes
    `EA <off> <seg>` (JMP FAR) to the overlay's new segment, plus a relocation for <seg>

Format (STARMAP.EXE, 2026-10-17): stub = 32-byte header `CD 3F 00 00 <u32 ovl_off> <u16 code>
<u16 fixups> <u16 n_entries> ...`, then n_entries x 5-byte entries at stub+0x20.

The result is for ANALYSIS only (the overlay manager is bypassed; the program is not meant to run).
Writes work/deoverlay/<EXE> and <EXE>.map.json (overlay idx -> new image segment, stub entries).
Usage:  py -3 tools/deoverlay.py STARMAP.EXE [--dgroup 0x326B]
"""
import argparse, json, struct
from common import ROOT
import dos_addr

ENTRY0, ENTRY_LEN = 0x20, 5


def segment_table(exe):
    """The FBOV segment table: image segment of every linker segment, in table order."""
    _s, segtbl, nseg = struct.unpack_from("<III", exe.data, exe.end + 4)
    return [struct.unpack_from("<H", exe.data, segtbl + 8 * i)[0] for i in range(nseg)]


def fixed_overlay_code(exe, o, base):
    """Overlay `o`'s code with every fixup applied for a load segment of `base`.

    A fixup word in overlay code is NOT an image segment: it is a segment-table INDEX x 8
    (selector-like). Verified 2026-10-17 over all 5,656 overlay far calls: index reading lands on
    4,449 prologues + 599 overlay stub entries + 608 in-bounds starts (asm RTL/graphics helpers,
    e.g. 0000:05FE, the root's own most-called routine), 0 invalid; reading the word as an image
    segment lands on 815 prologues. Raises on any word that is not a valid index.
    """
    st = segment_table(exe)
    code = bytearray(exe.data[o["file"]:o["file"] + o["size"]])
    fx = exe.data[o["file"] + o["size"]:o["file"] + o["size"] + o["fixups"]]
    sites = []
    for (f,) in struct.iter_unpack("<H", fx):
        if f + 2 > len(code):
            raise SystemExit(f"overlay {o['idx']}: fixup {f:#x} outside code ({len(code):#x})")
        w = struct.unpack_from("<H", code, f)[0]
        if w % 8 or w // 8 >= len(st):
            raise SystemExit(f"overlay {o['idx']}: fixup word {w:#x} at {f:#x} is not a segment-table index")
        struct.pack_into("<H", code, f, (st[w // 8] + base) & 0xFFFF)
        sites.append(f)
    return code, sites


def deoverlay(name, dgroup_seg):
    exe = dos_addr.Exe(name)
    d = exe.data
    image = bytearray(exe.image)
    relocs = []                                     # (seg, off) pairs, image-relative
    nrel, lfarlc = struct.unpack_from("<H", d, 6)[0], struct.unpack_from("<H", d, 0x18)[0]
    for i in range(nrel):
        off, seg = struct.unpack_from("<HH", d, lfarlc + 4 * i)
        relocs.append((seg, off))
    # first free paragraph above both the image and DGROUP's 64 KiB span
    start = max((len(image) + 15) // 16, dgroup_seg + 0x1000)
    seg = (start + 0xFF) & ~0xFF                    # round up to a tidy segment for readability
    image.extend(b"\0" * (seg * 16 - len(image)))
    omap = []
    for o in exe.overlays:
        code, sites = fixed_overlay_code(exe, o, 0)   # index x 8 -> image segment; MZ reloc adds load seg
        fx = sites
        image.extend(code)
        for f in sites:
            relocs.append((seg, f))
        stub = o["stub_seg"] * 16                   # image-relative linear
        entries = []
        for k in range(o["entries"]):
            p = stub + ENTRY0 + k * ENTRY_LEN
            if image[p:p + 2] != b"\xcd\x3f":
                raise SystemExit(f"overlay {o['idx']} entry {k}: expected CD 3F at image {p:#x}")
            target = struct.unpack_from("<H", image, p + 2)[0]
            image[p:p + 5] = b"\xea" + struct.pack("<HH", target, seg)
            relocs.append(((p + 3) >> 4, (p + 3) & 0xF))  # the <seg> word of the far jump
            entries.append(dict(stub=f"{o['stub_seg']:04X}:{ENTRY0 + k * ENTRY_LEN:04X}", target=f"{target:04X}"))
        omap.append(dict(idx=o["idx"], stub_seg=f"{o['stub_seg']:04X}", new_seg=f"{seg:04X}",
                         file=f"{o['file']:#x}", size=o["size"], fixups=len(fx), entries=entries))
        seg += (len(code) + 15) // 16
        image.extend(b"\0" * (seg * 16 - len(image)))
    # new MZ header: same entry/stack/alloc, bigger relocation table and image
    hdr_len = (0x1C + 4 * len(relocs) + 15) // 16 * 16
    total = hdr_len + len(image)
    h = bytearray(d[:0x1C])
    struct.pack_into("<HH", h, 2, total % 512, (total + 511) // 512)
    struct.pack_into("<HH", h, 6, len(relocs), hdr_len // 16)
    struct.pack_into("<H", h, 0x18, 0x1C)
    struct.pack_into("<H", h, 0x1A, 0)              # overlay number 0
    table = b"".join(struct.pack("<HH", off, s) for s, off in relocs)
    out = bytes(h) + table + b"\0" * (hdr_len - 0x1C - len(table)) + bytes(image)
    return out, omap, len(exe.image)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--dgroup", type=lambda s: int(s, 0), default=0x326B,
                    help="root DGROUP image segment (STARMAP: 0x326B, derived by table voting)")
    a = ap.parse_args()
    out, omap, root_len = deoverlay(a.exe, a.dgroup)
    dst = ROOT / "work" / "deoverlay"
    dst.mkdir(parents=True, exist_ok=True)
    (dst / a.exe).write_bytes(out)
    (dst / (a.exe + ".map.json")).write_text(json.dumps(dict(
        source=a.exe, root_image_len=root_len, dgroup_seg=f"{a.dgroup:04X}", overlays=omap), indent=1))
    print(f"{a.exe}: {len(omap)} overlays placed at {omap[0]['new_seg']}..{omap[-1]['new_seg']} "
          f"(image segs); {sum(o['fixups'] for o in omap)} fixups -> relocations; "
          f"{sum(len(o['entries']) for o in omap)} stub entries -> JMP FAR; {len(out)} B -> {dst / a.exe}")


if __name__ == "__main__":
    main()
