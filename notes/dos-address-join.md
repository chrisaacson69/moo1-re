# DOS address join — runtime (DOSBox) ↔ EXE file offset

Verified live 2026-10-16 with `tools/dos_addr.py live` against the Steam copy (stock DOSBox 0.74,
`dosboxMOO1.conf`), read-only process-memory reads, no debugger. Work in **linear** addresses
(`seg×16+off`); raw seg:off pairs are not comparable across tools.

## The formulas

| Where the file offset lies | Runtime ↔ file |
|---|---|
| **Root module** `[header, image_end)` | `linear = B×16 + (file_off − header)`, `B = PSP + 0x10`; relocated words read `file word + B` |
| **FBOV overlay** (after `image_end` + 16-byte `FBOV` header) | overlay loads at `<buffer seg>:0000`, so `file_off = image_end + 16 + ovl_off + runtime_off` |
| Ghidra (MzLoader, base `0x1000`) | the root formula with `B = 0x1000`. **Unverified**: Ghidra isn't installed |

`B` (and the overlay buffer segment) varies from run to run: Steam/DOSBox gave PSP `0192`, and zappatic's eXoDOS run implies `0813`.
ORION and STARMAP chain-exec into the **same** slot (both observed at PSP `0192`).

## Evidence (this run: PSP 0192, B = 01A2 for both EXEs)

| Check | ORION.EXE (main menu) | STARMAP.EXE (save loaded, star map) |
|---|---|---|
| PSP observed (`CD 20`, MCB owner = PSP) | ✔ 0192 | ✔ 0192 |
| Relocation words = file + B | 1899/1900 | 2990/2991 |
| Verified tables (`notes/table-sweep.md`) at predicted address | 12/12 | 19/19 |
| Root code diffs (excl. relocations) | 494, all on file-zero bytes (CS-resident variables) | 744: 389 on file-zero bytes, 355 inside the overlay-manager/stub segments (≥ `3176:0`); **0 in instructions** |
| Overlays resident at `seg:0000` | #52 @3317, #53 @3514 | #71 @4DF4, #75 @514E |

- The **one relocation miss** in each EXE is the same kind of thing (STARMAP image `0x31764`, ORION `0x1EC04`): a far pointer the
  runtime overwrites with a saved BIOS vector (`F000:…`). It's data, not a formula failure.
- **Overlay point, end to end:** zappatic's fleet-count write site `4E23:1839` (`inc word [CC86]`) →
  static: file `0x6CE39` = overlay #71 + `0x1839` (his "~6C39" was misheard `6CE39`) → live: RAM
  `4DF4:1839` = `FF 06 86 CC 33 C9 EB 5A`. Same offset, different buffer segment per run.
- **zappatic's `0x7DD0` delta** (RAM `0813:92FC` ≡ Ghidra `1468:4B7C`): both land on file `0xC9FC`
  (`33 C9 EB 41`, unique in STARMAP) if his PSP was `0813`. This is consistent, but his PSP was never observed.

## Overlay layout (STARMAP)
`FBOV` header: `u32 size, u32 segtable_file_off (0x35020), u32 nseg (96)`. Segment table entries are
`u16 seg, maxoff, flags, minoff`, and `flags & 2` marks overlaid code (25 entries). Each stub
`CD 3F 00 00 <u32 ovl_off> <u16 code> <u16 fixups> <u16 entries>`. The code and fixup blocks tile the
appended area exactly. `py -3 tools/dos_addr.py map STARMAP.EXE` lists them all.
All 19 verified STARMAP tables sit in the root, and so does the whole DGROUP. Overlays hold code only.

## What's left
- Ghidra: load each overlay as its own segment at `:0000` (a splitter = `map` + slicing; fixups
  are in the `fixups` block after each overlay's code). Not built.
- Watchpoints still need a debugger (the shipped 0.74 has none). The address join no longer does.
