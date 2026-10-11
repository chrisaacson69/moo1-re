"""Fetch the third-party reference oracles into refs/ (gitignored).

- 1oom (GPLv2 recreation of the v1.3 engine), checked out at the pinned commit (or a commit
  whose src/ and doc/ are identical — ONEOOM_EQUIV). Sources, in order: an existing clone, the
  local bundle refs/1oom.bundle, then each mirror. A full-history bundle is (re)written after
  every successful fetch, so the project survives 1oom's hosts disappearing.
- zappatic's savegame/RAM struct JSON (https://zappatic.net/moo), downloaded as-is.
Neither is redistributed by this repo. Re-running is idempotent.
"""
import subprocess, urllib.request
from common import (ONEOOM, ONEOOM_MIRRORS, ONEOOM_PIN, ONEOOM_EQUIV, ONEOOM_BUNDLE,
                    ZAPPATIC, ZAPPATIC_FILES)


def git(*a, cwd=None, check=True):
    return subprocess.run(["git", *a], cwd=cwd, check=check, capture_output=True, text=True)


def has(commit):
    return git("cat-file", "-e", commit + "^{commit}", cwd=ONEOOM, check=False).returncode == 0


def fetch_1oom():
    sources = ([str(ONEOOM_BUNDLE)] if ONEOOM_BUNDLE.exists() else []) + ONEOOM_MIRRORS
    if not (ONEOOM / ".git").exists():
        ONEOOM.parent.mkdir(parents=True, exist_ok=True)
        for src in sources:
            if git("clone", "-q", src, str(ONEOOM), check=False).returncode == 0:
                print("1oom cloned from", src)
                break
        else:
            raise SystemExit("could not clone 1oom from any source: " + ", ".join(sources))
    for src in sources:                       # make sure the pin is present if any source has it
        if has(ONEOOM_PIN):
            break
        git("fetch", "-q", src, "+refs/heads/*:refs/remotes/fetched/*", cwd=ONEOOM, check=False)
    target = next((c for c in [ONEOOM_PIN, *ONEOOM_EQUIV] if has(c)), None)
    if target is None:
        raise SystemExit(f"neither pin {ONEOOM_PIN} nor equivalents {ONEOOM_EQUIV} found")
    if target != ONEOOM_PIN:
        print(f"WARNING: pin {ONEOOM_PIN} unavailable; using {target} (src/ and doc/ identical)")
    git("checkout", "-q", target, cwd=ONEOOM)
    git("bundle", "create", str(ONEOOM_BUNDLE), "--all", cwd=ONEOOM)
    head = git("rev-parse", "--short", "HEAD", cwd=ONEOOM).stdout.strip()
    print(f"1oom @ {head}; bundle {ONEOOM_BUNDLE.stat().st_size // 1024} KiB")


def fetch_zappatic():
    ZAPPATIC.mkdir(parents=True, exist_ok=True)
    for name, url in ZAPPATIC_FILES.items():
        dest = ZAPPATIC / name
        if not dest.exists():
            urllib.request.urlretrieve(url, dest)
        print(name, dest.stat().st_size, "bytes")


if __name__ == "__main__":
    fetch_1oom()
    fetch_zappatic()
