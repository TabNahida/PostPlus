#!/usr/bin/env python3
"""Run the separate PostPlus processes for development; Ctrl+C stops the group."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import time

SERVICES = ("auth", "storage", "filter", "transfer", "delivery", "smtp", "pop3", "imap", "web")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True, type=Path)
    parser.add_argument("--config", default="config/postplus.json", type=Path)
    args = parser.parse_args()
    binaries = args.bin_dir.resolve()
    config = args.config.resolve()
    if not config.is_file():
        parser.error(f"Config does not exist: {config}")
    children = []
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        for service in SERVICES:
            executable = binaries / ("postplus-" + service + (".exe" if os.name == "nt" else ""))
            children.append((service, subprocess.Popen(
                [str(executable), "--config", str(config)],
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)))
        while not stopping:
            for service, child in children:
                if child.poll() is not None:
                    raise RuntimeError(f"{service} exited with code {child.returncode}; stopping service group")
            time.sleep(0.2)
    finally:
        for _, child in reversed(children):
            if child.poll() is None:
                child.terminate()
        deadline = time.monotonic() + 35
        for _, child in reversed(children):
            try:
                child.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    main()
