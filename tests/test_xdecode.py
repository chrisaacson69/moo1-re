"""The two independent save layouts must agree on every checked field of every fixture.
Skips (not passes) if the third-party refs haven't been fetched: run tools/fetch_refs.py."""
import pathlib, sys, unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from common import ZAPPATIC  # noqa: E402


@unittest.skipUnless((ZAPPATIC / "zapdebugger-moo.json").exists(), "refs not fetched")
class TestCrossDecode(unittest.TestCase):
    def test_fixtures_agree(self):
        from xdecode import compare, Layout
        lay = Layout()
        fixtures = sorted((ROOT / "fixtures").glob("*.GAM"))
        self.assertTrue(fixtures)
        for f in fixtures:
            bad = [r for r in compare(f, lay) if r[7] != "OK"]
            self.assertEqual(bad, [], f.name)

    def test_zappatic_layout_is_22_bytes_short(self):
        # Known gap: his block list stops at 0xE686; 1oom reads end/winner/election up to 0xE69C.
        from xdecode import Layout, SAVE_LEN
        self.assertEqual(SAVE_LEN - Layout().total, 22)


if __name__ == "__main__":
    unittest.main()
