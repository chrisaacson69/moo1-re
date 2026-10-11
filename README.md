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
| `tools/fetch_refs.py` | 1oom pinned (GitHub → GitLab fallback, source-identical equivalent accepted) + full-history offline bundle `refs/1oom.bundle`; zappatic JSON. |

## Findings so far

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
  ABSENT (16) are almost all 1oom UI layout. The one game-logic ABSENT, `ai_p3_tbl_w` (AI slider
  weights), is probably inline constants in the original — and 1oom reads column [2] for the eco
  weight (`game_ai_classic.c:1888`) and swaps prop/planetology columns (`:2016-2017`): faithful
  quirk or 1oom slip? **Needs the disassembly.**

Write-ups and the stream/OSG/1oom cross-checks live in the vault (`research/gaming/moo1/`).

## Next

- Struct tables (`game_parsed.c` monsters/Guardian, ship tech) need field widths — extend the sweep.
- Resolve `ai_p3_tbl_w` against STARMAP.EXE code.
- More fixtures across turns/events; decode the events block and diplomacy fields on real saves.
- Map the DOSBox load segment ↔ Ghidra delta for STARMAP.EXE (`method/data-first-re.md`, open question).
