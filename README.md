# moo1-re

Reverse engineering **Master of Orion 1** (1993, DOS v1.3) toward exact, independently verified
mechanics. Data-first: saves and static tables before code. Tools are stdlib Python 3.11+.

## Setup

```bash
cp config.example.toml config.toml        # set game_dir to your MOO1 v1.3 install
py -3 tools/fetch_refs.py                 # 1oom @42e9c0b + zappatic's struct JSON → refs/ (gitignored)
py -3 -m unittest discover -s tests -v
```

## Tools

| Tool | What it verifies |
|---|---|
| `tools/xdecode.py <save.GAM>` | Decodes a save via zappatic's JSON **and** via 1oom's `game_save_moo13.c` offsets; every field must agree on offset and value. Turn-1 fixture: 41/41. |
| `tools/exe_find.py <1oom file> <symbol>` | Parses a static table from 1oom's C source and byte-searches `ORION.EXE`/`STARMAP.EXE` (int8/16, signed/unsigned). A full match = 1oom's table is the original's. |
| `tools/table_sweep.py` | Runs that check over **every** hard-coded integer table in 1oom → `notes/table-sweep.md` (generated; regenerate, don't edit). |
| `tools/struct_sweep.py` | Same for 1oom's **struct** tables (ship tech, monsters, start ships): enums/`#define`s resolved from 1oom's headers, records located by constant **stride**, sliding-window fallback when the original layout differs → `notes/struct-sweep.md` (generated). |
| `tools/disasm.py <exe> <root|N> <off> [n]` | Capstone 16-bit disassembly by module offset (root image or overlay N); `--grep` operand search. STARMAP DGROUP = image seg 0x326B. |
| `tools/fetch_refs.py` | 1oom pinned (GitHub → GitLab fallback, source-identical equivalent accepted) + full-history offline bundle `refs/1oom.bundle`; zappatic JSON. |
| `tools/dos_addr.py map\|where\|root\|live` | DOSBox runtime address ↔ EXE file offset: MZ root formula + Borland FBOV overlay table. `live` reads a running DOSBox (read-only) and verifies the formula against every relocation, the table-sweep hits and the resident overlays → `notes/dos-address-join.md`. |

## Findings so far

- **The static↔runtime address join is solved by formula** (live, 2026-10-16): root `linear = (PSP+0x10)×16 + file_off − header`. Both EXEs pass: 2990/2991 + 1899/1900 relocations, 31/31 verified tables. FBOV overlays load at `seg:0000`, so a runtime offset is the in-overlay offset (zappatic's fleet-count `inc` = overlay #71+0x1839, observed). See `notes/dos-address-join.md`.

- Save = 59,036 B; zappatic's layout is 22 B short (end/winner/election tail at 0xE686–0xE69B).
- Stored year = shown year − 2299.
- Starting race-relations table: `ORION.EXE` file offset `0x22D6A`, int16, identical to 1oom —
  Klackon↔Silicoid = −12 (the OSG's +7 is wrong).

- **1oom table fidelity (sweep, 53 integer tables):** 23 byte-identical in v1.3, incl. all the
  game-logic ones the sweep can see — AI special-device chances (124), both tech-cost reduction
  curves, battle hit-chance, diplomacy `reldiff`, nebula shapes, race table, starting relations.
  New-game data lives in `ORION.EXE`; AI/tech/battle/diplomacy tables in `STARMAP.EXE`. Most C
  `uint8_t`/`int` tables are stored as **16-bit words** in the original. The single NEAR hit
  (`colortbls_sd`) is a lookalike: 1oom zero-pads past the original's end (EXE continues `NONE NUC…`).
  ABSENT (16) are almost all 1oom UI layout. The one game-logic ABSENT, `ai_p3_tbl_w`, is a real
  table in v1.3 with **15-word rows** (6 columns 1oom drops) — resolved by disassembly:
  **1oom's eco weight reads the wrong column** (an unflagged 1oom bug that inverts the Ecologist
  personality); the prop/plan order is faithful. See `notes/ai-slider-weights.md`.

- **Ship-tech data is binary-verified (struct sweep):** weapons (64/64), computers, engines (9/9),
  armor (14/14), shields, jammers, specials and hulls (4/4) all sit in `STARMAP.EXE` `0x36D36–0x3856E`
  with **values identical to 1oom**. Unmatched indices are the all-zero NONE records or low-entropy
  windows skipped by the guard — inspected by hand (specials 1/3), they match too. The original
  *layouts* differ from 1oom's structs: weapons 48 B/record vs 1oom's packing (one extra word before
  cost), computers 30 B (= 1oom's 14 fields + trailing name pointer), specials 50 B (name+description near pointers first,
  one field relocated), hulls 18 B = `cost, space, hits, ?6, index×6, power, defense, 0, name_ptr`.
  `tbl_monster` and `tbl_startship` are ABSENT — expected: 1oom's monster table is a derived
  ("parsed") battle form, start ships are built from enums/names.

Write-ups and the stream/OSG/1oom cross-checks live in the vault (`research/gaming/moo1/`).

## Next

- Monsters/Guardian: neither 1oom's HP progression (2,000…10,000) nor the OSG's (6,000…10,000) is stored as a
  constant-stride table in either EXE (a 6,000…10,000 hit was Huge-hull computer costs) — likely computed or
  LBX-held; needs code or a runtime read on known difficulties.
- What do the AI table's extra columns (4, 11–14) drive?
- More fixtures across turns/events; decode the events block and diplomacy fields on real saves.
- Map the DOSBox load segment ↔ Ghidra delta for STARMAP.EXE (`method/data-first-re.md`, open question).
