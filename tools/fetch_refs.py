"""Fetch the third-party reference oracles into refs/ (gitignored).

- 1oom (GPLv2 recreation of the v1.3 engine), checked out at the pinned commit.
- zappatic's savegame/RAM struct JSON (https://zappatic.net/moo), downloaded as-is.
Neither is redistributed by this repo. Re-running is idempotent.
"""
import subprocess, urllib.request
from common import ONEOOM, ONEOOM_URL, ONEOOM_PIN, ZAPPATIC, ZAPPATIC_FILES


def git(*a, cwd=None):
    subprocess.run(["git", *a], cwd=cwd, check=True)


def main():
    if not (ONEOOM / ".git").exists():
        ONEOOM.parent.mkdir(parents=True, exist_ok=True)
        git("clone", "-q", ONEOOM_URL, str(ONEOOM))
    git("checkout", "-q", ONEOOM_PIN, cwd=ONEOOM)
    print("1oom @", subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ONEOOM,
                                   capture_output=True, text=True).stdout.strip())
    ZAPPATIC.mkdir(parents=True, exist_ok=True)
    for name, url in ZAPPATIC_FILES.items():
        dest = ZAPPATIC / name
        if not dest.exists():
            urllib.request.urlretrieve(url, dest)
        print(name, dest.stat().st_size, "bytes")


if __name__ == "__main__":
    main()
