# moo1-re — app-local rules

Governed by the **kernel** (`~/.claude/CLAUDE.md` — grounding + how-Chris-works) and the **project
SDK** (`Vault/projects/CLAUDE.md`). This file only adds what's specific to this repo.

## What this is

Reverse engineering Master of Orion 1 (1993, DOS, **v1.3** — the Steam build) to get exact, verified
mechanics. First DOS target in the vault; method thesis: Vault `method/data-first-re.md`.
`STARMAP.EXE` runs the turn engine; `ORION.EXE` is setup/menus **and holds new-game data** (not
"just a loader"). Feeds `moo1-opening-optimizer`.

## The oracles — and their roles (decided with Chris, 2026-10-11)

| Oracle | Role | Notes |
|---|---|---|
| **The v1.3 binaries + real saves** | final arbiter | read in place via `config.toml`; never committed |
| **1oom** (`refs/1oom` @ `42e9c0b`) | the code; formulas + save offsets | GPL recreation. **Read-only** — we cannot contribute upstream (and it's dormant). Before trusting a code path as v1.3 behaviour, check `doc/list_gamediff.txt`, `doc/list_pbxnum.txt`, `WASBUG` comments. |
| **OSG** (Official Strategy Guide) | documented *intent* | predates v1.3; where it disagrees with the code, **the code wins**. OCR text in Vault `raw/books/moo1-osg/`. |
| **zappatic** (stream + struct JSON in `refs/zappatic`) | third-party layout | probed on a different (eXoDOS) build |
| **Chris** | bug lore, OSG print/PDF | ask in batches; diplomacy is a black box to him — resolve that by RE |
| RotP | not ground truth | modernized (diplomacy changed) |
| FreeOrion | **not an oracle** | inspired, not canonical |

## Grounding rules specific to this repo

- **Agreement of two independently-derived artifacts is the verifier**, not a re-run of our own
  code (`tools/xdecode.py`: zappatic layout × 1oom offsets; `tools/exe_find.py`: 1oom table × EXE bytes).
- **Never hand-copy a table.** `exe_find.py` parses 1oom's C initializer directly.
- **"Not found" is not a refutation.** A table absent from the EXEs may be computed, packed or in an LBX.
- **Cite 1oom as `file:line @42e9c0b`.** If the pin moves, re-verify cites.
- **Third-party material stays in `refs/`** (gitignored); game files are never committed. Saves only
  as curated `fixtures/` with their on-screen facts recorded.
- **Read measurements through known v1.3 bugs** (e.g. tech-screen % shows half the true chance; 32,000
  ship-stack display wrap). Check the bug catalogues before naming something a mechanic.

## Harvest back to the vault

Confirmed mechanics → Vault `research/gaming/moo1/` (the three-way cross-check pages are the
current drafts); generalizable method → `method/`. Pointer page: Vault `projects/moo1-re/README.md`.
