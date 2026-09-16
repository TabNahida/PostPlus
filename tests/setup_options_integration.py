"""CLI-only setup listeners, canonical URLs and certificate control authorization."""
import argparse
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import time
from integration import ROOT
from setup_integration import NativeServer, assert_ports_closed, http


def run(binaries, directory):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1",0))
        port=reservation.getsockname()[1]
    server=NativeServer(binaries,directory/"custom.json",port,directory,"custom",ROOT/"web",
                        ["--setup-bind","127.0.0.1","--setup-host","localhost"])
    try:
        server.wait(server.setup_ready)
        assert any(f"http://localhost:{port}/setup" in line for line in server.lines)
        headers={"Host":f"localhost:{port}","X-Setup-Token":server.token}
        assert http(port,"GET","/api/setup",headers=headers)[0]==200
        assert http(port,"GET","/api/setup",headers={**headers,"Host":f"127.0.0.1:{port}"})[0]==403
        assert http(port,"GET","/api/setup",headers={**headers,"Origin":"http://evil.example"})[0]==403
        for route in ("/api/setup/acme/status","/api/setup/acme/terms?directory=staging"):
            assert http(port,"GET",route,headers={"Host":f"localhost:{port}"})[0]==403
        assert http(port,"GET","/api/setup/acme/status",headers=headers)[2]["state"]=="idle"
        assert http(port,"POST","/api/setup/acme/start",{"directory":"http://127.0.0.1/"},headers)[0]==400
        assert http(port,"GET","/size.js",headers={"Host":f"localhost:{port}"})[0]==200
        assert http(port,"GET","/acme.js",headers={"Host":f"localhost:{port}"})[0]==200
    finally:server.close()

    # Test remote-bind setup using the existing local certificate and a scoped
    # trust context. The client verifies the certificate chain and localhost name.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1",0))
        secure_port=reservation.getsockname()[1]
    certificate=ROOT/"tests/fixtures/localhost-test-only.crt"
    private_key=ROOT/"tests/fixtures/localhost-test-only.key"
    context=ssl.create_default_context(cafile=str(certificate))
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    assert context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED
    secure_config=directory/"remote-https.json"
    secure=NativeServer(binaries,secure_config,secure_port,directory,"remote-https",ROOT/"web",
                        ["--setup-bind","0.0.0.0","--setup-host","localhost",
                         "--setup-tls-certificate",str(certificate),"--setup-tls-private-key",str(private_key)])
    try:
        secure.wait(secure.setup_ready)
        assert any(f"https://localhost:{secure_port}/setup" in line for line in secure.lines)
        assert any("Remote HTTPS setup is enabled" in line for line in secure.lines)
        origin=f"https://localhost:{secure_port}"
        headers={"Host":f"localhost:{secure_port}","Origin":origin,"X-Setup-Token":secure.token}
        deadline=time.monotonic()+10
        while True:
            try:
                status,_,page=http(secure_port,"GET","/setup",headers=headers,context=context)
                break
            except ConnectionRefusedError:
                assert time.monotonic()<deadline,"HTTPS setup listener did not become ready"
                time.sleep(0.05)
        assert status==200 and b'id="setup-unlock"' in page
        status,_,response=http(secure_port,"GET","/api/setup",headers=headers,context=context)
        assert status==200 and response["ok"] and response["completing_existing"] is False,response
        assert response["defaults"]["bind"]=="127.0.0.1", "temporary bind must not change permanent listener defaults"
        assert http(secure_port,"GET","/api/setup",headers={"Host":headers["Host"]},context=context)[0]==403
        for rejected in ({**headers,"Host":f"127.0.0.1:{secure_port}"},
                         {**headers,"Host":f"evil.example:{secure_port}"},
                         {**headers,"Origin":"https://evil.example"},
                         {**headers,"Origin":f"http://localhost:{secure_port}"},
                         {**headers,"Origin":"https://localhost:1"}):
            status,_,response=http(secure_port,"GET","/api/setup",headers=rejected,context=context)
            assert status==403 and response["ok"] is False,(rejected,status,response)
        # Origin checks also protect mutations before body validation/provisioning.
        status,_,response=http(secure_port,"POST","/api/setup",{},
                               {**headers,"Origin":"https://evil.example"},context=context)
        assert status==403 and response["code"]=="invalid_origin",response
        assert http(secure_port,"GET","/api/setup/acme/status",headers=headers,context=context)[2]["state"]=="idle"
        assert not secure_config.exists() and not secure.services_ready.is_set()
    finally:secure.close()
    assert_ports_closed({"setup":secure_port})
    binary=binaries/("postplus.exe" if os.name=="nt" else "postplus")
    for arguments in (["--setup-port","0"],["--setup-port","65536"],["--setup-bind","bad-ip"],
                      ["--setup-bind","0.0.0.0"],["--setup-host","https://localhost/"],
                      ["--setup-tls-certificate","missing.pem"]):
        result=subprocess.run([str(binary),"--config",str(directory/"invalid.json"),"--web-root",str(ROOT/"web"),*arguments],
                              capture_output=True,text=True,timeout=10)
        assert result.returncode!=0,(arguments,result.stdout,result.stderr)
    assert not (directory/"invalid.json").exists()
    print("PASS custom HTTP/HTTPS setup bind/port/hostname, verified TLS, Host/Origin/token checks and CLI validation",flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir",type=Path,required=True)
    args=parser.parse_args()
    directory=ROOT/"build/test-runs"/("setup-options-"+secrets.token_hex(6))
    directory.mkdir(parents=True)
    run(args.bin_dir.resolve(),directory)
