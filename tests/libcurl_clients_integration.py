#!/usr/bin/env python3
"""Exercise IMAP/POP3 using libcurl, independently of Python protocol clients."""
import argparse
from pathlib import Path
import secrets
import shutil
import subprocess

from integration import PASSWORD, ROOT, Suite


def run(s):
    curl = shutil.which("curl")
    if not curl:
        print("SKIP libcurl client: curl is unavailable", flush=True)
        return
    version = subprocess.check_output([curl, "--version"], text=True)
    protocols = next((line.lower().split()[1:] for line in version.splitlines() if line.startswith("Protocols:")), [])
    if not all(protocol in protocols for protocol in ("imap", "imaps", "pop3", "pop3s")):
        print("SKIP libcurl client: installed curl lacks mail protocols", flush=True)
        return
    certificate = ROOT / "tests/fixtures/localhost-test-only.crt"
    s.config.update(tls_certificate=str(certificate),
                    tls_private_key=str(ROOT / "tests/fixtures/localhost-test-only.key"),
                    allow_insecure_auth=False)
    s.save()
    for service in ("auth", "storage", "imap", "pop3"):
        s.start(service)
    user = "curl-client@localhost"
    assert s.rpc("auth", op="create", username=user, password=PASSWORD)["ok"]
    raw = b"From: sender@localhost\r\nTo: curl-client@localhost\r\nSubject: libcurl compatibility\r\n\r\nIndependent protocol client.\r\n.dot line\r\n"
    assert s.rpc("storage", op="deliver", username=user, raw=raw, delivery_id="curl-mail")["ok"]
    assert s.rpc("storage", op="folder_create", username=user, folder="Client folder")["ok"]
    def request(protocol, port, path="", command=None, mechanism="PLAIN", starttls=False):
        args = [curl, "--silent", "--show-error", "--max-time", "10", "--cacert", str(certificate),
                "--user", user+":"+PASSWORD, "--login-options", "AUTH="+mechanism]
        if starttls:
            args += ["--ssl-reqd"]
        if command:
            # libcurl versions differ on whether custom IMAP control replies
            # appear on stdout. Inspect only received server lines as well.
            args += ["--verbose", "--request", command]
        args += [f"{protocol}://localhost:{s.ports[port]}/{path}"]
        result = subprocess.run(args, capture_output=True, timeout=15)
        received = b"\n".join(line[2:] for line in result.stderr.splitlines() if line.startswith(b"< "))
        assert result.returncode == 0, (protocol, port, command, result.returncode, received)
        return result.stdout + (received if command else b"")
    listed = request("imaps", "imaps", command='LIST "" "*"')
    assert b'"INBOX"' in listed and b'"Client folder"' in listed, listed
    fetched = request("imaps", "imaps", "INBOX/;UID=1", mechanism="LOGIN")
    assert fetched == raw, fetched
    headers = request("imap", "imap", "INBOX", "UID FETCH 1:* (UID FLAGS RFC822.SIZE ENVELOPE BODYSTRUCTURE)", starttls=True)
    assert b"FETCH" in headers and b"libcurl compatibility" in headers and b"BODYSTRUCTURE" in headers, headers
    listing = request("pop3s", "pop3s", mechanism="PLAIN")
    assert b"1 " in listing, listing
    assert request("pop3s", "pop3s", "1", mechanism="LOGIN") == raw
    assert request("pop3", "pop3", "1", starttls=True) == raw
    print("PASS independent libcurl client: IMAP folders/list/headers/body and POP3 list/body over implicit TLS and STARTTLS", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True, type=Path)
    args = parser.parse_args()
    directory = ROOT / "build/test-runs" / ("libcurl-clients-" + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()
