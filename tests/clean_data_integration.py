#!/usr/bin/env python3
"""Native cleanup checks against disposable databases only."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from integration import ROOT
from setup_integration import NativeServer, assert_ports_closed, child_processes, http
from storage_integration import Services, free_port


def check(binary_directory, directory, xmake_command):
    services = Services(binary_directory, directory)
    services.config.update(domain="cleanup.example.test", setup_complete=True,
                           max_mailbox_bytes=1536 * 1024 * 1024)
    config_path = directory / "postplus.json"
    executable = binary_directory / ("postplus-clean-data.exe" if os.name == "nt" else "postplus-clean-data")
    run = lambda *args: subprocess.run([str(executable), "--config", str(config_path), *args],
                                     capture_output=True, text=True, timeout=20)
    try:
        absent = run()
        assert absent.returncode == 0 and "No configuration found" in absent.stdout
        assert not (directory / "data").exists()
        services.start("auth")
        services.start("storage")
        assert services.rpc("auth", "create", username="admin@cleanup.example.test", password="cleanup-secret-123!", admin=True)["ok"]
        assert services.rpc("storage", "deliver", username="admin@cleanup.example.test", raw="Subject: Cleanup\r\n\r\nMail\r\n", delivery_id="cleanup-job")["ok"]
        original = config_path.read_bytes()
        data = directory / "data"
        first = run()
        assert first.returncode == 1 and "stop all PostPlus services" in first.stderr, first
        assert config_path.read_bytes() == original and (data / "auth.sqlite3").is_file()
        services.stop("auth")
        second = run()
        assert second.returncode == 1 and "stop all PostPlus services" in second.stderr, second
        assert config_path.read_bytes() == original and (data / "storage.sqlite3").is_file()
        services.stop("storage")

        sentinels = [data / "logs" / "postplus.jsonl", data / "certificates" / "private-key.pem",
                     data / "other.sqlite3", directory / "service-token", directory / "postplus.json.previous"]
        for sentinel in sentinels:
            sentinel.parent.mkdir(parents=True, exist_ok=True)
            sentinel.write_text("preserve this file", encoding="utf-8")
        (data / "auth.sqlite3-journal").write_bytes(b"old journal")
        (data / "storage.sqlite3-shm").write_bytes(b"old shared memory")
        snapshot = {path: path.read_bytes() for path in data.iterdir() if path.is_file()}
        dry = run("--dry-run")
        assert dry.returncode == 0 and "Would remove:" in dry.stdout, dry
        assert config_path.read_bytes() == original
        assert not list(directory.glob("postplus.json.backup-*"))
        assert all(path.read_bytes() == content for path, content in snapshot.items())
        if xmake_command:
            dry_task = subprocess.run([xmake_command, "clean-data", "--config=" + str(config_path), "--dry-run"],
                                      cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=120)
            assert dry_task.returncode == 0 and "Would remove:" in dry_task.stdout, dry_task
            assert config_path.read_bytes() == original

        # Validate all target paths before deleting the first database or
        # changing setup state. A hard link also avoids a Windows admin requirement.
        (data / "storage.sqlite3-shm").unlink()
        os.link(sentinels[2], data / "storage.sqlite3-shm")
        linked = run()
        assert linked.returncode == 1 and "hard-linked" in linked.stderr, linked
        assert config_path.read_bytes() == original and (data / "auth.sqlite3").is_file()
        (data / "storage.sqlite3-shm").unlink()
        try:
            (data / "storage.sqlite3-shm").symlink_to(sentinels[2])
        except OSError:
            print("SKIP symbolic-link fixture: host does not permit creating symlinks")
        else:
            symbolic = run()
            assert symbolic.returncode == 1 and ("link" in symbolic.stderr or "reparse" in symbolic.stderr), symbolic
            assert config_path.read_bytes() == original and (data / "auth.sqlite3").is_file()
            (data / "storage.sqlite3-shm").unlink()
            linked_directory = directory / "linked-data"
            linked_directory.symlink_to(data, target_is_directory=True)
            try:
                redirected = json.loads(original)
                redirected["data_dir"] = str(linked_directory) + os.sep
                config_path.write_text(json.dumps(redirected), encoding="utf-8")
                through_link = run()
                assert through_link.returncode == 1 and ("link" in through_link.stderr or "reparse" in through_link.stderr), through_link
                assert (data / "auth.sqlite3").is_file()
            finally:
                config_path.write_bytes(original)
                linked_directory.unlink()
        (data / "storage.sqlite3-shm").mkdir()
        invalid = run()
        assert invalid.returncode == 1 and "non-regular" in invalid.stderr, invalid
        assert config_path.read_bytes() == original and (data / "auth.sqlite3").is_file()
        (data / "storage.sqlite3-shm").rmdir()

        cleaned = run()
        assert cleaned.returncode == 0, cleaned
        assert not (data / "auth.sqlite3").exists() and not (data / "storage.sqlite3").exists()
        assert not (data / "auth.sqlite3-journal").exists()
        assert all(path.read_text(encoding="utf-8") == "preserve this file" for path in sentinels)
        assert (data / ".postplus-data.lock").is_file()
        updated = json.loads(config_path.read_text(encoding="utf-8"))
        assert updated.pop("setup_required") is True
        assert updated == json.loads(original)
        backups = list(directory.glob("postplus.json.backup-*"))
        assert len(backups) == 1 and backups[0].read_bytes() == original
        # Cleaning again is harmless and keeps the first-run marker enabled.
        repeated = run()
        assert repeated.returncode == 0 and "Removed 0 database files" in repeated.stdout, repeated

        # The explicit reset marker must reopen even a completed installation.
        # Read/unlock the wizard only; do not provision an administrator or mail services.
        reset_config = config_path.read_bytes()
        assert json.loads(reset_config)["setup_complete"] is True
        setup_port = free_port()
        launcher = NativeServer(binary_directory, config_path, setup_port, directory,
                                "after-cleanup", web_root=ROOT / "web")
        try:
            launcher.wait(launcher.setup_ready)
            assert any("setup is required" in line for line in launcher.lines)
            assert any(f"http://127.0.0.1:{setup_port}/setup" in line for line in launcher.lines)
            assert launcher.token and launcher.token != services.token
            deadline = time.monotonic() + 10
            while True:
                try:
                    status, _, page = http(setup_port, "GET", "/setup")
                    break
                except ConnectionRefusedError:
                    assert time.monotonic() < deadline, "reset setup listener did not become ready"
                    time.sleep(0.05)
            assert status == 200 and b'id="setup-unlock"' in page
            assert http(setup_port, "GET", "/api/setup")[0] == 403
            status, _, response = http(setup_port, "GET", "/api/setup",
                                       headers={"X-Setup-Token": launcher.token})
            assert status == 200 and response["ok"] and response["completing_existing"], response
            defaults = response["defaults"]
            assert defaults["domain"] == "cleanup.example.test"
            assert defaults["admin_username"] == "admin@cleanup.example.test"
            assert Path(defaults["data_dir"]).resolve() == data.resolve()
            assert defaults["max_mailbox_bytes"] == services.config["max_mailbox_bytes"]
            assert defaults["max_message_bytes"] == services.config["max_message_bytes"]
            assert defaults["timeout_seconds"] == services.config["timeout_seconds"]
            assert all(defaults["ports"][name] == port for name, port in services.ports.items())
            assert config_path.read_bytes() == reset_config, "opening setup must not rewrite the retained config"
            assert not (data / "auth.sqlite3").exists() and not (data / "storage.sqlite3").exists()
            assert not launcher.services_ready.is_set() and not child_processes(launcher.process.pid)
        finally:
            launcher.close()
        assert_ports_closed({"setup": setup_port})
    finally:
        services.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", required=True, type=Path)
    parser.add_argument("--xmake", help="Also check the xmake clean-data task")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="postplus-clean-data-") as temporary:
        check(args.bin_dir.resolve(), Path(temporary), args.xmake)
    print("Native cleanup locking, dry-run, link refusal, database removal and retained-settings setup re-entry checks passed.")


if __name__ == "__main__":
    main()
