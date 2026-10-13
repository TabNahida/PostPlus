#!/usr/bin/env python3
"""Exercise the systemd installer's safe preview and setup checks on Linux."""
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/install-systemd.sh"
BINARIES = ("postplus", "postplus-update", "postplus-admin", "postplus-auth", "postplus-storage",
            "postplus-filter", "postplus-transfer", "postplus-delivery",
            "postplus-smtp", "postplus-pop3", "postplus-imap", "postplus-web")


def quote(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def run(*arguments, env=None):
    return subprocess.run(["bash", str(SCRIPT), *map(str, arguments)],
                          capture_output=True, text=True, timeout=15, env=env)


def main():
    if sys.platform != "linux":
        print("SKIP systemd installer test: Linux required")
        return
    assert run("--help").returncode == 0
    with tempfile.TemporaryDirectory(prefix='postplus systemd %$ ') as temporary:
        root = Path(temporary)
        install = root / 'release %$ name'
        working = root / 'work %$ "name'
        config_dir = working / "config"
        config = config_dir / 'postplus $ "name.json'
        install.mkdir()
        config_dir.mkdir(parents=True)
        for directory in (root, install, working):
            directory.chmod(0o755)
        config_dir.chmod(0o777)
        for name in BINARIES:
            binary = install / name
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
        config.write_text('{"setup_complete": true, "domain": "example.test"}\n', encoding="utf-8")
        config.chmod(0o644)

        shim = root / "shim"
        shim.mkdir()
        systemctl_log = root / "systemctl.log"
        fake_systemctl = shim / "systemctl"
        fake_systemctl.write_text('#!/bin/sh\nprintf called >> "$POSTPLUS_SYSTEMCTL_LOG"\n', encoding="utf-8")
        fake_systemctl.chmod(0o755)
        environment = dict(os.environ, PATH=str(shim) + os.pathsep + os.environ["PATH"],
                           POSTPLUS_SYSTEMCTL_LOG=str(systemctl_log))

        user = pwd.getpwuid(os.getuid()).pw_name
        if os.getuid() == 0:
            user = "nobody"
        base_options = ("--install-dir", install, "--working-dir", working,
                        "--config", config)
        options = (*base_options, "--user", user, "--dry-run")
        result = run(*options, env=environment)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert not systemctl_log.exists(), "dry run called systemctl"
        recovery = install / ".postplus-recovery"
        assert not recovery.exists(), "dry run wrote the recovery copy"
        if shutil.which("systemd-analyze"):
            # A real installation creates this executable before enabling the unit.
            shutil.copy2(install / "postplus-update", recovery)
            unit = root / "postplus.service"
            unit.write_text(result.stdout.split("\n\n", 1)[1], encoding="utf-8")
            verify = subprocess.run(["systemd-analyze", "verify", "--man=no", str(unit)],
                                    capture_output=True, text=True, timeout=15)
            assert verify.returncode == 0, (verify.stdout, verify.stderr, unit.read_text())
        assert "WorkingDirectory=" + str(working.resolve()).replace("%", "%%") + "/." in result.stdout
        expected = (f"ExecStart=:{quote(str(install.resolve() / 'postplus'))} "
                    f"--config {quote(str(config.resolve()))}")
        assert expected in result.stdout, result.stdout
        expected_recovery = (f"ExecStartPre=:{quote(str(recovery.resolve()))} "
                             f"--recover-launcher --config {quote(str(config.resolve()))}")
        assert expected_recovery in result.stdout, result.stdout
        assert "postplus-update" not in expected_recovery, "recovery must survive updater replacement"
        for setting in ("User=" + user, "Restart=on-failure", "RestartForceExitStatus=75",
                        "Environment=POSTPLUS_SERVICE_MANAGER=systemd", "KillMode=mixed",
                        "TimeoutStopSec=130s", "AmbientCapabilities=CAP_NET_BIND_SERVICE"):
            assert setting in result.stdout, setting
        default = run(*base_options, "--dry-run", env=environment)
        assert default.returncode == 0, (default.stdout, default.stderr)
        assert "User=" + pwd.getpwuid(os.getuid()).pw_name in default.stdout
        if not recovery.exists():
            shutil.copy2(install / "postplus-update", recovery)
        recovery.unlink()
        recovery.symlink_to(install / "postplus-update")
        unsafe = run(*options, env=environment)
        assert unsafe.returncode != 0 and "refusing to replace" in unsafe.stderr
        recovery.unlink()
        os.link(install / "postplus-update", recovery)
        unsafe = run(*options, env=environment)
        assert unsafe.returncode != 0 and "hard-linked recovery helper" in unsafe.stderr
        recovery.unlink()

        unsupported_install = root / 'unsupported "install'
        unsupported_install.mkdir()
        result = run("--install-dir", unsupported_install, "--config", config, "--dry-run")
        assert result.returncode != 0 and "systemd cannot execute" in result.stderr

        config.write_text('{"domain": "example.test"}\n', encoding="utf-8")
        result = run(*options)
        assert result.returncode != 0 and "setup is not complete" in result.stderr
        config.write_text('{"setup_complete": true, "setup_required": true}\n', encoding="utf-8")
        result = run(*options)
        assert result.returncode != 0 and "setup is required" in result.stderr
        config.write_text('{"setup_complete": true}\n', encoding="utf-8")
        helper = install / "postplus-update"
        helper.chmod(0o644)
        result = run(*options)
        assert result.returncode != 0 and "missing executable" in result.stderr and "postplus-update" in result.stderr
        helper.chmod(0o755)
        if os.getuid() == 0:
            helper.chmod(0o700)
            result = run(*options)
            assert result.returncode != 0 and f"{user} cannot execute" in result.stderr and "postplus-update" in result.stderr
            helper.chmod(0o755)
        helper.unlink()
        result = run(*options)
        assert result.returncode != 0 and "missing executable" in result.stderr and "postplus-update" in result.stderr
        helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        helper.chmod(0o755)
        (install / "postplus-web").unlink()
        result = run(*options)
        assert result.returncode != 0 and "missing executable" in result.stderr
    print("PASS systemd installer preview, recovery helper requirements, escaping, and setup checks")


if __name__ == "__main__":
    main()
