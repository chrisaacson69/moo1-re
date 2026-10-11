"""Verify a 1oom static table against the ORIGINAL executables by byte search.

The cheapest binary oracle: no debugger, no segment/relocation join. Parse a C array straight out of
1oom's source (so nothing is hand-copied), encode it as int8/int16/uint8/uint16 little-endian, and
search ORION.EXE / STARMAP.EXE. A full-table hit means 1oom's table is byte-identical to v1.3; the
reported file offset is where the original keeps it. No hit is NOT a refutation — the table may be
computed, packed differently, or stored in an LBX — so report it as "not found", nothing more.

Usage:
  py -3 tools/exe_find.py src/game/game_new.c tbl_orion_race_relation
  py -3 tools/exe_find.py --values 0 1 1 1 1 1 1 1 1 1
"""
import argparse, re, struct
from common import ONEOOM, game_dir

EXES = ["ORION.EXE", "STARMAP.EXE"]
ENC = {"int8": "b", "uint8": "B", "int16": "<h", "uint16": "<H"}


def c_array(path, symbol):
    """Integer literals of `symbol`'s initializer in a 1oom C file (decimal or hex)."""
    src = open(path, encoding="latin1").read()
    m = re.search(re.escape(symbol) + r"\s*(\[[^=]*\])?\s*=\s*\{", src)
    if not m:
        raise SystemExit(f"{symbol} not found in {path}")
    i, depth = m.end() - 1, 0
    for j in range(i, len(src)):
        depth += {"{": 1, "}": -1}.get(src[j], 0)
        if depth == 0:
            body = re.sub(r"/\*.*?\*/|//[^\n]*", "", src[i:j + 1], flags=re.S)
            return [int(t, 0) for t in re.findall(r"-?(?:0x[0-9a-fA-F]+|\d+)", body)]
    raise SystemExit("unbalanced initializer")


def encode(vals, enc):
    out = b""
    for v in vals:
        try:
            out += struct.pack(ENC[enc], v)
        except struct.error:
            return None  # value out of range for this width
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?", help="path inside refs/1oom, e.g. src/game/game_new.c")
    ap.add_argument("symbol", nargs="?")
    ap.add_argument("--values", nargs="+", type=lambda s: int(s, 0))
    a = ap.parse_args()
    vals = a.values or c_array(ONEOOM / a.file, a.symbol)
    print(f"{len(vals)} values; first 10: {vals[:10]}")
    found = False
    for exe in EXES:
        data = (game_dir() / exe).read_bytes()
        for enc in ENC:
            pat = encode(vals, enc)
            if pat is None:
                continue
            hits, k = [], data.find(pat)
            while k >= 0:
                hits.append(hex(k))
                k = data.find(pat, k + 1)
            if hits:
                found = True
                print(f"  {exe:12} {enc:6} FULL MATCH at {', '.join(hits)}")
    if not found:
        print("  not found in any EXE/encoding (not a refutation — see docstring)")


if __name__ == "__main__":
    main()
