"""Decode a MOO1 v1.3 save (*.GAM) two independent ways and compare field by field.

A: zappatic's published struct JSON (refs/zappatic/*.json) — layout found by RAM/save probing.
B: offsets transcribed from 1oom src/game/game_save_moo13.c @42e9c0b (line refs in each check).

Agreement on offset AND value from two independently-derived layouts is the verifier
(verification-independence): neither decoder is checked against a second copy of itself.

Usage:  py -3 tools/xdecode.py fixtures/turn1-psilon-simple-medium.GAM
"""
import json, re, struct, sys, collections
from common import ZAPPATIC

W = {'u8': 1, 's8': 1, 'bool8': 1, 'char': 1, 'u16': 2, 's16': 2, 'bool16': 2,
     'u32': 4, 's32': 4, 'bool32': 4}
FMT = {'u8': 'B', 's8': 'b', 'u16': '<H', 's16': '<h', 'u32': '<I', 's32': '<i'}
SAVE_LEN = 59036  # 1oom game_save_moo13.c:14 SAVE_MOO13_LEN


class Layout:
    """zappatic's JSON: block order of the save file + the struct library it imports."""

    def __init__(self, zdir=ZAPPATIC):
        dbg = json.load(open(zdir / 'zapdebugger-moo.json', encoding='utf8'))
        ana = json.load(open(zdir / 'zapbinanalysis-moo.json', encoding='utf8'))
        self.structs = {**dbg['structs'], **ana['structs']}
        self.enums = dbg['enums']
        self.blocks, o = {}, 0
        for blk in ana['blocks']:
            self.blocks[blk['name']] = (o, blk['type'])
            o += self.size(blk['type'])
        self.total = o

    def size(self, t):
        m = re.match(r'(.+?)\[(\d+)\]$', t)
        if m:
            return self.size(m.group(1)) * int(m.group(2))
        return W[t] if t in W else sum(self.size(f['type']) for f in self.structs[t]['fields'])

    def field(self, struct_name, field):
        o = 0
        for f in self.structs[struct_name]['fields']:
            if f['name'] == field:
                return o, f
            o += self.size(f['type'])
        raise KeyError(f'{struct_name}.{field}')

    def locate(self, block, field=None, idx=0):
        """-> (absolute offset, type, enum) for block[idx].field (or the block itself)."""
        bo, bt = self.blocks[block]
        st = re.match(r'(.+?)\[', bt).group(1) if '[' in bt else bt
        if field is None:
            return bo + idx * self.size(st), st, None
        fo, f = self.field(st, field)
        return bo + idx * self.size(st) + fo, f['type'], f.get('enum')

    def enum_name(self, enum, v):
        e = self.enums.get(enum, {})
        return e.get(str(v)) if isinstance(e, dict) else None


def read(buf, off, t):
    if t.startswith('char'):
        n = int(re.search(r'\[(\d+)\]', t).group(1))
        return buf[off:off + n].split(b'\0')[0].decode('latin1')
    return struct.unpack_from(FMT[t], buf, off)[0]


def checks(buf, lay):
    """Yield (label, zappatic (off,type,enum), 1oom (off,type), 1oom line)."""
    gs, G = 'game-settings', 'gamestate'
    yield 'players', lay.locate(gs, 'player-array-size'), (0xe2d2, 'u16'), 148
    yield 'difficulty', lay.locate(gs, 'difficulty'), (0xe2d4, 'u16'), 151
    yield 'galaxy stars', lay.locate(gs, 'planet-array-size'), (0xe2d6, 'u16'), 154
    yield 'galaxy size', lay.locate(gs, 'galaxy-size'), (0xe2d8, 'u16'), 152
    yield 'Z unknown4 = 1oom galaxy_w', lay.locate(gs, 'unknown4'), (0xe2da, 'u16'), 155
    yield 'Z unknown5 = 1oom galaxy_h', lay.locate(gs, 'unknown5'), (0xe2dc, 'u16'), 156
    yield 'Z map-width = 1oom galaxy_maxx', lay.locate(gs, 'galaxy-map-width'), (0xe2de, 'u16'), 157
    yield 'Z map-height = 1oom galaxy_maxy', lay.locate(gs, 'galaxy-map-height'), (0xe2e0, 'u16'), 158
    yield 'year (stored; shown = +2299)', lay.locate(G, 'current-year'), (0xe232, 'u16'), 159
    yield 'nebula count', lay.locate(G, 'nebulae-count'), (0xe238, 'u16'), 153
    yield 'enroute count', (lay.locate('ships-en-route-array-size')[0], 'u16', None), (0xe1b6, 'u16'), 160
    yield 'transport count', (lay.locate('ships-transports-array-size')[0], 'u16', None), (0xe1b8, 'u16'), 161
    nplayers = read(buf, 0xe2d2, 'u16')
    for i in range(nplayers):
        eb = 0x7118 + i * 0xdd4  # 1oom :269
        yield f'player{i} race', lay.locate('players', 'race', i), (eb, 'u8'), 270
        yield f'player{i} banner', lay.locate('players', 'banner-color', i), (eb + 2, 'u8'), 271
        yield f'player{i} emperor', (lay.locate('player-names', None, i)[0], 'char[15]', None), \
            (0xe1ba + i * 15, 'char[15]'), 178
    stars = read(buf, 0xe2d6, 'u16')
    owned = [i for i in range(stars) if read(buf, i * 0xb8 + 0x36, 's16') == 0]
    for i in owned[:1] + [0]:
        pb = i * 0xb8  # 1oom :184
        yield f'planet{i} name', lay.locate('planets', 'name', i), (pb, 'char[12]'), 185
        yield f'planet{i} x', lay.locate('planets', 'x-coordinate', i), (pb + 0xc, 'u16'), 186
        yield f'planet{i} owner', lay.locate('planets', 'colonized-by-player', i), (pb + 0x36, 's16'), 205
        yield f'planet{i} pop', lay.locate('planets', 'current-population', i), (pb + 0x3a, 'u16'), 208
        yield f'planet{i} factories', lay.locate('planets', 'factory-count', i), (pb + 0x3e, 'u16'), 210


def compare(path, lay=None):
    lay = lay or Layout()
    buf = open(path, 'rb').read()
    rows = [('save length', '', len(buf), '', '', SAVE_LEN, 14,
             'OK' if len(buf) == SAVE_LEN else 'DIFF')]
    for label, (zo, zt, ze), (bo, bt), line in checks(buf, lay):
        zv, bv = read(buf, zo, zt), read(buf, bo, bt)
        verdict = 'OK' if (zo == bo and zv == bv) else ('VALUE-ONLY' if zv == bv else 'DIFF')
        rows.append((label, hex(zo), zv, (lay.enum_name(ze, zv) or '') if ze else '', hex(bo), bv, line, verdict))
    return rows


def main():
    rows = compare(sys.argv[1])
    print(f"{'field':34} {'Z off':>7} {'Z val':>12} {'Z enum':10} {'1oom off':>8} {'1oom val':>12} line  verdict")
    for r in rows:
        print(f"{r[0]:34} {r[1]:>7} {str(r[2]):>12} {str(r[3]):10} {r[4]:>8} {str(r[5]):>12} {r[6]:>4}  {r[7]}")
    tally = collections.Counter(r[7] for r in rows)
    print(dict(tally))
    sys.exit(0 if set(tally) == {'OK'} else 1)


if __name__ == '__main__':
    main()
