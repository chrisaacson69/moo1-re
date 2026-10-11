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

## Findings so far

- Save = 59,036 B; zappatic's layout is 22 B short (end/winner/election tail at 0xE686–0xE69B).
- Stored year = shown year − 2299.
- Starting race-relations table: `ORION.EXE` file offset `0x22D6A`, int16, identical to 1oom —
  Klackon↔Silicoid = −12 (the OSG's +7 is wrong).

Write-ups and the stream/OSG/1oom cross-checks live in the vault (`research/gaming/moo1/`).

## Next

- Sweep every static table in 1oom through `exe_find.py` (a fidelity map of 1oom vs v1.3).
- More fixtures across turns/events; decode the events block and diplomacy fields on real saves.
- Map the DOSBox load segment ↔ Ghidra delta for STARMAP.EXE (`method/data-first-re.md`, open question).
