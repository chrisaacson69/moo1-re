"""Shared paths/config. Everything is relative to the repo root; machine paths live in config.toml."""
import pathlib, tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
REFS = ROOT / "refs"
ONEOOM = REFS / "1oom"
ZAPPATIC = REFS / "zappatic"
ONEOOM_URL = "https://github.com/1oom-fork/1oom.git"
ONEOOM_PIN = "42e9c0b"          # every 1oom file:line we cite is against this commit
ZAPPATIC_FILES = {
    "zapdebugger-moo.json": "https://zappatic.net/js/moo/zapdebugger-moo.json",
    "zapbinanalysis-moo.json": "https://zappatic.net/js/moo/zapbinanalysis-moo.json",
}


def game_dir() -> pathlib.Path:
    cfg = ROOT / "config.toml"
    if not cfg.exists():
        raise SystemExit("missing config.toml — copy config.example.toml and set game_dir")
    return pathlib.Path(tomllib.loads(cfg.read_text())["game_dir"])
