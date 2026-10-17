# AI slider weights (1oom `ai_p3_tbl_w`) — v1.3 vs 1oom

Resolved 2026-10-17 by disassembling STARMAP.EXE with `tools/disasm.py` (Capstone, 16-bit).

## How it was found
1. `table_sweep.py` reported `ai_p3_tbl_w` ABSENT; rows/columns individually absent too.
2. Fingerprint: 1oom's routine compares the eco slider to 96/91/81/71. A raw-byte scan for
   `83 /7 ib` (cmp imm8) with 0x60→0x5B→0x51→0x47 in order hits exactly once: **STARMAP root,
   image offset 0x138D5** (Capstone's linear sweep had desynced before it — scan bytes, then disassemble).
3. Data segment: DGROUP image seg **0x326B** (14/16 verified tables referenced from code at that base;
   next best 7/16). players = `DS:0x786E` (stride 0xDD4); planets = far ptr `DS:0xCB72` (stride 0xB8).

## The original table: `DS:0x094C` (file `0x367FC`), 7 rows × **15 words** (row stride 0x1E)
| row | trait2 | ship def ind eco | col4 | comp cons ff plan prop | wpn | cols 11–14 |
|---|---|---|---|---|---|---|
| 0 | Diplomat | 1 2 4 1 | 5 | 2 2 4 2 3 | 3 | 75 10 40 20 |
| 1 | Militarist | 4 1 2 1 | 5 | 3 1 4 2 1 | 5 | 20 0 30 30 |
| 2 | Expansionist | 2 4 1 1 | 5 | 1 1 3 5 2 | 4 | 35 5 20 20 |
| 3 | Technologist | 1 2 3 1 | 6 | 4 2 3 2 2 | 3 | 35 5 40 -10 |
| 4 | Industrialist | 1 2 4 1 | 5 | 1 5 4 1 2 | 3 | 40 5 30 -50 |
| 5 | Ecologist | 1 1 2 4 | 5 | 1 2 4 1 5 | 3 | 50 10 20 10 |
| 6 | (at war) | 4 1 1 1 | 6 | 2 2 4 2 1 | 5 | 20 5 40 50 |

1oom's 9 columns = original cols 0–3 and 5–9, **values identical**. Col 10 (weapons) = 16 − Σ(5..9)
in every row, so 1oom's `rnd_1_n(16)` + "else weapons" is equivalent. Cols 4 and 11–14 are not in
this 1oom table — used elsewhere? (open).

## Code (root, around 0x137FF / 0x13F20)
```
w_ship = T[ti][0]; w_def = w_ship+T[ti][1]; w_ind = w_def+T[ti][2]; w_eco = w_ind+T[ti][3]   ; [bx+94c..952]
... leftover loop: r1 = rnd(13), r2 = rnd(8) ...                                              ; 13B4C, 13B59
r = rnd(16); cumulative over cols 5,6,7,9,8,10 (= 1oom [4],[5],[6],[8],[7], weapons)          ; 13F20–13F9F
```

## Verdicts
- **Eco weight — 1OOM BUG (unflagged).** v1.3 uses column **3**; 1oom `game_ai_classic.c:1888`
  @42e9c0b uses `[2]` (industry). Not in `list_gamediff.txt`/`list_pbxnum.txt`. Effect on the
  leftover-slider draw (eco vs tech share of a 13-sided roll):

  | trait2 | eco v1.3 → 1oom | tech v1.3 → 1oom |
  |---|---|---|
  | Diplomat | 1 → 4 /13 | 5 → 2 /13 |
  | Militarist | 1 → 2 | 5 → 4 |
  | Expansionist | 1 → 1 | 5 → 5 |
  | Technologist | 1 → 3 | 6 → 4 |
  | Industrialist | 1 → 4 | 5 → 2 |
  | Ecologist | **4 → 2** | 5 → 7 |
  | at war | 1 → 1 | 6 → 6 |

  v1.3's design intent is visible: only the Ecologist favours eco. 1oom inverts it.
- **Research order prop `[8]` before plan `[7]` — FAITHFUL.** v1.3 sums cols 9 then 8 identically.
- **Weapons as remainder — EQUIVALENT** (see col 10).
