"""Unit checks for coverage_map's text extraction (pure regex/normalisation; no refs or game needed)."""
import pathlib, sys, unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import coverage_map as C  # noqa: E402


class TestExtraction(unittest.TestCase):
    def test_reko_ds_members(self):
        self.assertEqual(C.DSMEMBER.findall("x = ds->w7946 + ds->ptrCB72; y = ds->tCC84; ds->wordy"),
                         ["7946", "CB72", "CC84"])

    def test_c_string_literal(self):
        self.assertEqual(C.STR_C.findall(r'a = "Hi \"there\""; b = "x";'), [r'Hi \"there\"', "x"])

    def test_norm_text(self):
        self.assertEqual(C.norm_text("2 SHOTS, MIRVS TO 7"), "2 shots mirvs to 7")
        self.assertIsNone(C.norm_text("ab"))      # too short to carry identity


if __name__ == "__main__":
    unittest.main()
