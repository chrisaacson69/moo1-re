"""Shared paths/config. Everything is relative to the repo root; machine paths live in config.toml."""
import pathlib, tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
REFS = ROOT / "refs"
ONEOOM = REFS / "1oom"
ZAPPATIC = REFS / "zappatic"
ONEOOM_MIRRORS = [              # 1oom is dormant; try hosts in order (see its MIRRORS.md)
    "https://github.com/1oom-fork/1oom.git",
    "https://gitlab.com/1oom-fork/1oom.git",
]
ONEOOM_PIN = "42e9c0b"          # every 1oom file:line we cite is against this commit
# Commits with byte-identical src/ and doc/ (checked 2026-10-11: only MIRRORS.md/README.md differ).
# deeb34d is GitLab's head and the pin's parent's parent; acceptable if a host lacks the pin.
ONEOOM_EQUIV = ["deeb34d"]
ONEOOM_BUNDLE = REFS / "1oom.bundle"   # full-history offline backup, written by fetch_refs.py
ZAPPATIC_FILES = {
    "zapdebugger-moo.json": "https://zappatic.net/js/moo/zapdebugger-moo.json",
    "zapbinanalysis-moo.json": "https://zappatic.net/js/moo/zapbinanalysis-moo.json",
}


def game_dir() -> pathlib.Path:
    cfg = ROOT / "config.toml"
    if not cfg.exists():
        raise SystemExit("missing config.toml — copy config.example.toml and set game_dir")
    return pathlib.Path(tomllib.loads(cfg.read_text())["game_dir"])
