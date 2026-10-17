"""Overlay fixups must resolve far calls to real entry points (regression for the 2026-10-17 bug where
fixup words were read as image segments instead of segment-table index x 8). Needs config.toml."""
import pathlib, struct, sys, unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))


@unittest.skipUnless((ROOT / "config.toml").exists(), "no config.toml (game files)")
class TestOverlayFixups(unittest.TestCase):
    def test_far_calls_land_on_entry_points(self):
        import dos_addr, deoverlay
        exe = dos_addr.Exe("STARMAP.EXE")
        d, good, total = exe.data, 0, 0
        stub_segs = {o["stub_seg"] for o in exe.overlays}
        for o in exe.overlays:
            code, sites = deoverlay.fixed_overlay_code(exe, o, 0)
            for f in sites:
                if f >= 3 and code[f - 3] == 0x9A:                       # call far off:seg
                    off, seg = struct.unpack_from("<HH", code, f - 2)
                    t = exe.hdr + seg * 16 + off
                    total += 1
                    good += d[t:t + 3] == b"\x55\x8b\xec" or (seg in stub_segs and d[t:t + 2] == b"\xcd\x3f")
        self.assertGreater(total, 5000)
        self.assertGreater(good / total, 0.85, f"{good}/{total} far calls hit a prologue or stub entry")

    def test_rng_reached_from_overlays(self):
        import dos_addr, deoverlay
        exe = dos_addr.Exe("STARMAP.EXE")
        o = next(o for o in exe.overlays if o["idx"] == 82)
        code, _ = deoverlay.fixed_overlay_code(exe, o, 0)
        self.assertIn(b"\x9a\xdd\x00\x55\x1e", code)                     # call far 1E55:00DD (the RNG)


if __name__ == "__main__":
    unittest.main()
