#!/usr/bin/env python3
"""Exercise native helper transactions against an isolated fake installation."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import os

ROOT = Path(__file__).resolve().parents[1]


def sha(value):
    return hashlib.sha256(value).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    suffix = ".exe" if os.name == "nt" else ""
    helper = args.bin_dir.resolve() / ("postplus-update" + suffix)
    assert "verified update helper" in subprocess.check_output([str(helper), "--help"], text=True)
    directory = ROOT / "build/test-runs" / ("update-helper-" + secrets.token_hex(6))
    install, state = directory / "install", directory / "data/.updates"
    web = install / "web"
    web.mkdir(parents=True)
    job_id = secrets.token_hex(16)
    job_dir = state / job_id
    (job_dir / "modules").mkdir(parents=True)
    (job_dir / "backup").mkdir()
    sentinel = {"postplus-auth" + suffix: b"unrelated native module", "README.md": b"user edited README", "postplus.json": b"private config"}
    for name, body in sentinel.items():
        (install / name).write_bytes(body)
    (directory / "data/private.key").write_bytes(b"secret key bytes")
    path = "postplus-smtp" + suffix
    original, updated = b"original SMTP module", b"verified new SMTP module"
    (install / path).write_bytes(original)
    file_id = sha(path.encode())
    (job_dir / "modules" / file_id).write_bytes(updated)
    job = {"ok": True, "schema": 1, "job_id": job_id, "state": "staged", "version": "0.2.2",
           "install_directory": str(install.resolve()), "web_directory": str(web.resolve()),
           "services": ["smtp"], "requires_launcher_restart": False,
           "files": [{"path": path, "id": file_id, "sha256": sha(updated), "size": len(updated), "old_sha256": sha(original), "executable": True}],
           "installation_manifest": {"schema": 1, "repository": "TabNahida/PostPlus", "version": "0.2.2", "files": []}}
    (job_dir / "job.json").write_text(json.dumps(job), encoding="utf-8")
    common = ["--job", job_id, "--install", str(install.resolve()), "--web", str(web.resolve()), "--state", str(state.resolve())]
    def run(operation):
        result = subprocess.run([str(helper), operation, *common], text=True, capture_output=True, timeout=20)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    # The kernel lease serializes different helper/supervisor processes; closing
    # the descriptor releases it without a stale crash-recovery directory.
    state.mkdir(parents=True, exist_ok=True)
    lock_path = state / ".lock"
    lock_path.write_bytes(b"\0")
    with lock_path.open("r+b") as lease:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(lease.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lease.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        blocked = subprocess.run([str(helper), "--apply", *common], text=True, capture_output=True, timeout=20)
        assert blocked.returncode != 0 and "Another update transaction is active" in blocked.stderr, blocked
        assert (install / path).read_bytes() == original
        assert json.loads((job_dir / "job.json").read_text())["state"] == "staged"
    assert run("--apply")["state"] == "installed"
    assert (install / path).read_bytes() == updated
    assert run("--rollback")["state"] == "rolled_back"
    assert (install / path).read_bytes() == original
    for name, body in sentinel.items():
        assert (install / name).read_bytes() == body
    assert (directory / "data/private.key").read_bytes() == b"secret key bytes"
    assert (job_dir / "backup" / file_id).read_bytes() == original
    assert json.loads((job_dir / "job.json").read_text())["rolled_back"] is True
    # ExecStartPre's native helper lets systemd attempt the new launcher once,
    # then restores a generation that never committed readiness.
    boot_id = secrets.token_hex(16)
    boot_dir = state / boot_id
    (boot_dir / "modules").mkdir(parents=True)
    (boot_dir / "backup").mkdir()
    (boot_dir / "modules" / file_id).write_bytes(updated)
    boot_job = {**job, "job_id": boot_id, "requires_launcher_restart": True}
    stable = install / (".postplus-recovery" + suffix)
    shutil.copy2(helper, stable)
    stable_hash = sha(stable.read_bytes())
    updater_path = "postplus-update" + suffix
    updater_old, updater_bad = b"original updater module", b"\0invalid updated helper"
    (install / updater_path).write_bytes(updater_old)
    updater_id = sha(updater_path.encode())
    (boot_dir / "modules" / updater_id).write_bytes(updater_bad)
    boot_job["files"] = [*job["files"], {"path": updater_path, "id": updater_id,
        "sha256": sha(updater_bad), "size": len(updater_bad), "old_sha256": sha(updater_old), "executable": True}]
    (boot_dir / "job.json").write_text(json.dumps(boot_job), encoding="utf-8")
    config = directory / "postplus.json"
    secret = directory / "service-token"
    secret.write_text("f" * 64)
    config.write_text(json.dumps({"domain": "localhost", "service_token_file": str(secret.resolve()),
                                 "data_dir": str(state.parent.resolve()), "web_root": str(web.resolve())}), encoding="utf-8")
    (state / "relaunch.json").write_text(json.dumps({"job_id": boot_id, "config": str(config.resolve())}), encoding="utf-8")
    boot_common = ["--job", boot_id, "--install", str(install.resolve()), "--web", str(web.resolve()), "--state", str(state.resolve())]
    applied = subprocess.run([str(helper), "--apply", *boot_common], text=True, capture_output=True, timeout=20)
    assert applied.returncode == 0, applied.stderr
    assert (install / updater_path).read_bytes() == updater_bad
    recovery = [str(stable), "--recover-launcher", "--config", str(config.resolve())]
    for expected in ("installed", "rolled_back", "rolled_back"):
        result = subprocess.run(recovery, text=True, capture_output=True, timeout=20)
        assert result.returncode == 0 and json.loads(result.stdout)["state"] == expected, result
    assert (install / path).read_bytes() == original and (state / "relaunch.json").exists()
    assert (install / updater_path).read_bytes() == updater_old
    assert sha(stable.read_bytes()) == stable_hash, "module update replaced its recovery executable"
    print("PASS native update helper cross-process kernel lease, private-job install/rollback, hash-verified originals and unrelated binary/config/document/data preservation")


if __name__ == "__main__":
    main()
