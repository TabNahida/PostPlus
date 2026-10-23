#!/usr/bin/env python3
"""Offline, repeatable HTTP/RPC/SMTP benchmark using disposable integration fixtures.

Run the same command with two release binary directories and distinct labels/outputs.
No compilation, production configuration, public DNS, or external mail is involved.
Example:
  python scripts/benchmark_network.py --bin-dir build/pace-baseline \
    --web-root build/pace-baseline/web --config-template build/pace-baseline/example.json \
    --label before --output build/pace-benchmark/before.json
  python scripts/benchmark_network.py --compare before.json after.json
"""
import argparse
from collections import Counter
import concurrent.futures
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import smtplib
import statistics
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from integration import PASSWORD, Suite  # noqa: E402

SERVICES = ("auth", "storage", "filter", "transfer", "smtp", "web", "delivery")
USER = "benchmark@localhost"
HARNESS_FILES = ("scripts/benchmark_network.py", "tests/integration.py")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values, fraction):
    """Nearest-rank percentile; unsuccessful requests are excluded explicitly."""
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def process_sample(pid):
    """Return cumulative process CPU seconds and current RSS, or an honest error."""
    if os.name == "nt":
        from ctypes import wintypes

        class MemoryCounters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (field, ctypes.c_size_t) for field in (
                    "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                    "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD]
        handle = kernel.OpenProcess(0x0400 | 0x0010, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            created, exited, system, user = (wintypes.FILETIME() for _ in range(4))
            if not kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                          ctypes.byref(system), ctypes.byref(user)):
                raise ctypes.WinError(ctypes.get_last_error())
            memory = MemoryCounters()
            memory.cb = ctypes.sizeof(memory)
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb):
                raise ctypes.WinError(ctypes.get_last_error())
            cpu = sum((item.dwHighDateTime << 32) + item.dwLowDateTime for item in (system, user)) / 1e7
            return cpu, memory.WorkingSetSize
        finally:
            kernel.CloseHandle(handle)
    if sys.platform.startswith("linux"):
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        cpu = (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
        resident_pages = int(Path(f"/proc/{pid}/statm").read_text().split()[1])
        return cpu, resident_pages * os.sysconf("SC_PAGE_SIZE")
    raise RuntimeError("process CPU/RSS collection is supported on Windows and Linux only")


class ResourceMonitor:
    def __init__(self, suite):
        self.processes = {name: child.pid for name, child in suite.children.items()}
        self.done = threading.Event()
        self.peak_rss = 0
        self.errors = set()
        self.samples = 0

    def sample(self):
        cpu, rss = {}, 0
        for name, pid in self.processes.items():
            try:
                cpu[name], memory = process_sample(pid)
                rss += memory
            except (OSError, RuntimeError) as error:
                self.errors.add(f"{name}: {error}")
        if len(cpu) == len(self.processes):
            self.peak_rss = max(self.peak_rss, rss)
            self.samples += 1
        return cpu

    def start(self):
        self.before = self.sample()

        def monitor():
            while not self.done.wait(0.1):
                self.sample()

        self.thread = threading.Thread(target=monitor, daemon=True)
        self.thread.start()

    def finish(self, elapsed):
        self.done.set()
        self.thread.join()
        after = self.sample()
        complete = not self.errors and set(after) == set(self.before)
        cpu = sum(after[name] - self.before[name] for name in after) if complete else None
        return {
            "server_cpu_seconds": cpu,
            "server_cpu_percent_one_core": 100 * cpu / elapsed if cpu is not None else None,
            "server_peak_sampled_rss_bytes": self.peak_rss if complete else None,
            "sample_interval_seconds": 0.1, "samples": self.samples,
            "services": list(self.processes), "collection_errors": sorted(self.errors),
        }


def measure(suite, operation, count, concurrency):
    """Closed-loop fixed concurrency. Include connect/response/close in each latency."""
    ready = threading.Barrier(concurrency + 1)
    release = threading.Event()

    def worker(worker_index):
        latencies, failures = [], Counter()
        ready.wait()
        release.wait()
        for _ in range(worker_index, count, concurrency):
            start = time.perf_counter()
            try:
                operation()
            except Exception as error:
                failures[f"{type(error).__name__}: {str(error)[:180]}"] += 1
            else:
                latencies.append((time.perf_counter() - start) * 1000)
        return latencies, failures

    monitor = ResourceMonitor(suite)
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        jobs = [pool.submit(worker, index) for index in range(concurrency)]
        ready.wait()
        monitor.start()
        start = time.perf_counter()
        release.set()
        results = [job.result() for job in jobs]
        elapsed = time.perf_counter() - start
        resources = monitor.finish(elapsed)
    latencies = [latency for values, _ in results for latency in values]
    failures = sum((errors for _, errors in results), Counter())
    return {
        "attempted": count, "succeeded": len(latencies), "errors": sum(failures.values()),
        "error_details": dict(failures), "elapsed_seconds": elapsed,
        "throughput_success_per_second": len(latencies) / elapsed,
        "latency_ms": {name: percentile(latencies, fraction) for name, fraction in (
            ("p50", 0.5), ("p95", 0.95), ("p99", 0.99))},
        "resources": resources, "samples_ms": latencies,
    }


def message(size):
    header = ("From: sender@example.net\r\nTo: benchmark@localhost\r\n"
              "Subject: Local network benchmark\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n").encode()
    remaining = size - len(header) - 2
    if remaining < 1:
        raise ValueError("message size must accommodate the fixture headers")
    line = b"benchmark body " * 5 + b"\r\n"
    full_lines, tail = divmod(remaining, len(line))
    return header + line * full_lines + b"x" * tail + b"\r\n"


def run_round(args, round_index, result, checkpoint):
    """Keep the caller-owned round visible even if validation or cleanup fails."""
    result.update(round=round_index, status="running", stage="setup", warmups={},
                  workloads={}, validation={"errors": []})
    checkpoint()
    with tempfile.TemporaryDirectory(prefix="postplus-network-benchmark-") as directory:
        suite = None
        try:
            suite = Suite(args.bin_dir, Path(directory))
            # Pin the same template and overrides for both implementations.
            config = json.loads(args.config_template.read_text(encoding="utf-8-sig"))
            config.update({key: suite.config[key] for key in (
                "ports", "delivery_lock_port", "data_dir", "log_dir")})
            config.update(domain="localhost", admin_hostname="", webmail_shared_hostname="",
                          bind="127.0.0.1", admin_bind="127.0.0.1",
                          web_root=str(args.web_root), allow_insecure_auth=True,
                          max_connections=128, timeout_seconds=30, log_level="error",
                          max_message_bytes=65536, max_mailbox_messages=100000,
                          outbound_mode="disabled", clamav_host="", rspamd_enabled=False)
            suite.config = config
            suite.save()
            for service in SERVICES[:-1]:
                suite.start(service)
            assert suite.rpc("auth", op="create", username=USER, password=PASSWORD)["ok"]
            raw = message(args.message_bytes)
            for index in range(args.seed_messages):
                assert suite.rpc("storage", op="deliver", username=USER, raw=raw,
                                 delivery_id=f"seed-{index}")["ok"]
            status, headers, reply = suite.http("web", "POST", "/api/login", {
                "username": USER, "password": PASSWORD})
            assert status == 200 and reply["ok"], (status, reply)
            cookie = {"Cookie": headers["Set-Cookie"].split(";", 1)[0]}

            def health():
                status, _, reply = suite.http("web", "GET", "/health")
                assert status == 200 and reply.get("ok"), (status, reply)

            def mailbox():
                status, _, reply = suite.http("web", "GET", "/api/messages", headers=cookie)
                assert status == 200 and len(reply.get("messages", [])) == args.seed_messages, status

            def rpc():
                reply = suite.rpc("storage", op="stats")
                assert reply["ok"] and reply["messages"] == args.seed_messages, reply

            def smtp():
                with smtplib.SMTP("127.0.0.1", suite.ports["smtp"],
                                  local_hostname="benchmark.localhost", timeout=30) as client:
                    assert client.ehlo()[0] == 250
                    assert client.sendmail("sender@example.net", [USER], raw) == {}

            workloads = (
                ("http_health", health, args.http_requests, args.warmup),
                ("http_authenticated_mailbox", mailbox, args.mailbox_requests, args.warmup),
                ("http_storage_rpc", rpc, args.rpc_requests, args.warmup),
                ("smtp_durable_accept", smtp, args.smtp_messages, args.smtp_warmup),
            )
            for name, operation, count, warmup in workloads:
                result["stage"] = f"warmup:{name}"
                checkpoint()
                warmed = measure(suite, operation, warmup, args.concurrency)
                result["warmups"][name] = warmed
                checkpoint()
                if warmed["errors"]:
                    raise RuntimeError(f"{name} warmup failed: {warmed['error_details']}")
                result["stage"] = f"measurement:{name}"
                checkpoint()
                measured = measure(suite, operation, count, args.concurrency)
                result["workloads"][name] = measured
                checkpoint()
                print(f"round={round_index} {name}: {measured['throughput_success_per_second']:.1f}/s "
                      f"p95={measured['latency_ms']['p95']} ms errors={measured['errors']}", flush=True)
            accepted = args.smtp_warmup + result["workloads"]["smtp_durable_accept"]["succeeded"]
            result["stage"] = "validation:queue"
            result["validation"]["queue"] = {"status": "running", "expected_from_complete_sessions": accepted}
            checkpoint()
            queued = suite.rpc("storage", op="stats")
            queue_valid = queued["queued"] == accepted and queued["quarantined"] == 0
            result["validation"]["queue"].update(status="passed" if queue_valid else "failed", observed=queued)
            checkpoint()
            if not queue_valid:
                raise AssertionError("durable queue does not match completed SMTP sessions; "
                                     f"DATA can commit before QUIT fails: expected={accepted}, observed={queued}")
            # Count the durable queue and then verify full local delivery outside timing.
            # Suite readiness for delivery depends on its startup info log.
            suite.config["log_level"] = "info"
            suite.save()
            result["stage"] = "validation:delivery"
            result["validation"]["delivery"] = {"status": "running", "expected_messages": args.seed_messages + accepted}
            checkpoint()
            suite.start("delivery")
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                stats = suite.rpc("storage", op="stats")
                result["validation"]["delivery"]["observed"] = stats
                if stats["messages"] == args.seed_messages + accepted and stats["queued"] == 0:
                    break
                time.sleep(0.1)
            else:
                result["validation"]["delivery"]["status"] = "failed"
                raise AssertionError(f"delivery verification timed out: {stats}")
            result["validation"]["delivery"]["status"] = "passed"
            result["delivery_verified"] = {"accepted": accepted, "delivered": accepted, "queued": 0}
            result["status"] = "failed" if any(item["errors"] for item in result["workloads"].values()) else "complete"
            result["stage"] = "complete"
            checkpoint()
            return result
        except BaseException as error:
            failure = f"{type(error).__name__}: {error}"
            result.update(status="failed", failure=failure)
            result["validation"]["errors"].append({"stage": result["stage"], "error": failure})
            if result["stage"].startswith("validation:"):
                result["validation"][result["stage"].split(":", 1)[1]]["status"] = "failed"
            checkpoint()
            raise
        finally:
            if suite is not None:
                suite.close()


def summarize(rounds):
    summaries = {}
    for name in rounds[0]["workloads"]:
        results = [item["workloads"][name] for item in rounds]
        samples = [latency for result in results for latency in result["samples_ms"]]
        throughputs = [item["throughput_success_per_second"] for item in results]
        summaries[name] = {
            "throughput_median_per_second": statistics.median(throughputs),
            "throughput_min_per_second": min(throughputs), "throughput_max_per_second": max(throughputs),
            "latency_pooled_ms": {key: percentile(samples, fraction) for key, fraction in (
                ("p50", 0.5), ("p95", 0.95), ("p99", 0.99))},
            "attempted": sum(item["attempted"] for item in results),
            "errors": sum(item["errors"] for item in results),
        }
    return summaries


def compare(paths):
    before, after = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    for data in (before, after):
        hashes = data.get("harness_sha256", {})
        if data.get("schema_version") != 2 or any(
                not isinstance(hashes.get(name), str) or len(hashes[name]) != 64 or
                any(char not in "0123456789abcdef" for char in hashes[name]) for name in HARNESS_FILES):
            raise ValueError("benchmark lacks schema 2 harness/fixture SHA-256 evidence; "
                             "rerun both implementations with the current benchmark script")
    if before["harness_sha256"] != after["harness_sha256"]:
        raise ValueError("benchmark script or integration fixture SHA-256 differs; "
                         "rerun both implementations with the same harness and fixture")
    if any(data.get("status") != "complete" or "summary" not in data
           for data in (before, after)):
        raise ValueError("both benchmark runs must be complete before comparison")
    if before["parameters"] != after["parameters"]:
        raise ValueError("benchmark parameters/configuration differ; results are not directly comparable")
    if before["host"] != after["host"]:
        raise ValueError("benchmark hosts differ; run both measurements on the same host")
    if any(item["errors"] for data in (before, after) for item in data["summary"].values()):
        raise ValueError("a benchmark has request errors; resolve errors before comparing performance")
    print(f"Comparison: {before['label']} -> {after['label']}")
    print("| Workload | Before ops/s | After ops/s | Throughput change | Before p95 ms | After p95 ms |")
    print("|---|---:|---:|---:|---:|---:|")
    for name, old in before["summary"].items():
        new = after["summary"][name]
        old_rate, new_rate = old["throughput_median_per_second"], new["throughput_median_per_second"]
        print(f"| {name} | {old_rate:.2f} | {new_rate:.2f} | {(new_rate / old_rate - 1) * 100:+.1f}% "
              f"| {old['latency_pooled_ms']['p95']:.3f} | {new['latency_pooled_ms']['p95']:.3f} |")


def self_test():
    """Exercise evidence preservation with fake services; no sockets or binaries."""
    from contextlib import ExitStack, redirect_stdout
    import io
    from types import SimpleNamespace
    from unittest.mock import patch

    with tempfile.TemporaryDirectory(prefix="postplus-benchmark-self-test-") as directory:
        directory = Path(directory)
        template = directory / "example.json"
        template.write_text("{}", encoding="utf-8")
        args = SimpleNamespace(bin_dir=directory, web_root=directory, config_template=template,
                               seed_messages=2, message_bytes=4096, concurrency=1, warmup=1,
                               smtp_warmup=1, http_requests=2, mailbox_requests=2,
                               rpc_requests=2, smtp_messages=2)
        for fault in (None, "warmup", "queue", "quit", "delivery"):
            instances = []

            class FakeSuite:
                def __init__(self, binaries, path):
                    self.config = dict(ports={}, delivery_lock_port=1, data_dir=str(path), log_dir=str(path))
                    self.ports, self.children = {"smtp": 1}, {}
                    self.messages, self.queued, self.delivering, self.closed = 0, 0, False, False
                    instances.append(self)

                def save(self):
                    pass

                def start(self, service):
                    if service == "delivery":
                        self.delivering = True
                        if fault != "delivery":
                            self.messages += self.queued
                            self.queued = 0

                def close(self):
                    self.closed = True

                def rpc(self, service, **payload):
                    if payload["op"] == "deliver":
                        self.messages += 1
                    if payload["op"] == "stats":
                        queued = self.queued + (1 if fault == "queue" and self.queued else 0)
                        return dict(ok=True, messages=self.messages, queued=queued, quarantined=0)
                    return {"ok": True}

                def http(self, service, method, path, body=None, headers=None):
                    if path == "/api/messages" and fault == "warmup":
                        raise ConnectionResetError("controlled mailbox warmup failure")
                    return 200, {"Set-Cookie": "fixture=session; Path=/"}, {
                        "ok": True, "messages": [None] * self.messages}

            class FakeSMTP:
                def __init__(self, *positional, **keywords):
                    pass

                def __enter__(self):
                    return self

                def __exit__(self, *error):
                    if fault == "quit" and instances[-1].queued == 2:
                        raise OSError("controlled QUIT failure after durable DATA")

                def ehlo(self):
                    return 250, b"fixture"

                def sendmail(self, sender, recipients, raw):
                    instances[-1].queued += 1
                    return {}

            partial, snapshots = {}, []
            output = directory / "partial-round.json"

            def checkpoint():
                output.write_text(json.dumps(partial), encoding="utf-8")
                snapshots.append(json.loads(output.read_text(encoding="utf-8")))

            failure = None
            with ExitStack() as stack:
                stack.enter_context(patch.dict(globals(), Suite=FakeSuite))
                stack.enter_context(patch.object(smtplib, "SMTP", FakeSMTP))
                stack.enter_context(redirect_stdout(io.StringIO()))
                if fault == "delivery":
                    stack.enter_context(patch.object(time, "monotonic", side_effect=[0, 1, 61]))
                    stack.enter_context(patch.object(time, "sleep"))
                try:
                    run_round(args, 1, partial, checkpoint)
                except (AssertionError, RuntimeError) as error:
                    failure = error
            persisted = json.loads(output.read_text(encoding="utf-8"))
            assert instances[-1].closed
            if fault is None:
                assert failure is None and persisted["status"] == "complete"
                assert persisted["delivery_verified"]["delivered"] == 3
                assert all(any(len(item["workloads"]) == count and item["status"] == "running"
                               for item in snapshots) for count in range(1, 5))
            else:
                assert failure is not None and persisted["status"] == "failed"
                assert persisted["failure"] and persisted["validation"]["errors"]
                if fault == "warmup":
                    assert list(persisted["workloads"]) == ["http_health"]
                    assert persisted["warmups"]["http_authenticated_mailbox"]["errors"] == 1
                else:
                    assert len(persisted["workloads"]) == 4
                    validation = persisted["validation"]["delivery" if fault == "delivery" else "queue"]
                    assert validation["status"] == "failed" and "observed" in validation
                    if fault == "quit":
                        assert persisted["workloads"]["smtp_durable_accept"]["errors"] == 1
                        assert validation["observed"]["queued"] == 3
                        assert validation["expected_from_complete_sessions"] == 2
            print(f"PASS controlled {fault or 'successful checkpoints'} evidence preservation")

        before_path, after_path = directory / "before.json", directory / "after.json"
        complete = {"schema_version": 2, "status": "complete", "label": "fixture",
                    "harness_sha256": {name: sha256(ROOT / name) for name in HARNESS_FILES},
                    "parameters": {}, "host": {}, "summary": {"fixture": {
                        "errors": 0, "throughput_median_per_second": 1,
                        "latency_pooled_ms": {"p95": 1}}}}
        before_path.write_text(json.dumps(complete), encoding="utf-8")
        for change in ("matching", "legacy", "missing", *HARNESS_FILES, "failed"):
            candidate = json.loads(json.dumps(complete))
            if change == "legacy":
                candidate["schema_version"] = 1
                candidate.pop("harness_sha256")
            elif change == "missing":
                candidate["harness_sha256"].pop(HARNESS_FILES[1])
            elif change in HARNESS_FILES:
                candidate["harness_sha256"][change] = "0" * 64
            elif change == "failed":
                candidate["status"] = "failed"
            after_path.write_text(json.dumps(candidate), encoding="utf-8")
            failure = None
            with redirect_stdout(io.StringIO()):
                try:
                    compare((before_path, after_path))
                except ValueError as error:
                    failure = str(error)
            if change == "matching":
                assert failure is None
            elif change == "failed":
                assert failure and "complete" in failure
            else:
                assert failure and "rerun" in failure
            print(f"PASS comparison provenance check: {change}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bin-dir", type=Path)
    parser.add_argument("--web-root", type=Path, default=ROOT / "web")
    parser.add_argument("--config-template", type=Path, default=ROOT / "config/postplus.example.json")
    parser.add_argument("--label", default="benchmark")
    parser.add_argument("--source-revision", default="unspecified")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compare", type=Path, nargs=2, metavar=("BEFORE", "AFTER"))
    parser.add_argument("--self-test", action="store_true", help="run offline controlled-failure smoke checks")
    for name, default in (("rounds", 3), ("concurrency", 8), ("http-requests", 1000),
                          ("rpc-requests", 1000), ("mailbox-requests", 300), ("smtp-messages", 80),
                          ("warmup", 40), ("smtp-warmup", 8), ("seed-messages", 50), ("message-bytes", 4096)):
        parser.add_argument("--" + name, type=int, default=default)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.compare:
        compare(args.compare)
        return
    if not args.bin_dir or not args.output:
        parser.error("--bin-dir and --output are required for measurement")
    parameters = {key: getattr(args, key) for key in (
        "rounds", "concurrency", "http_requests", "rpc_requests", "mailbox_requests", "smtp_messages",
        "warmup", "smtp_warmup", "seed_messages", "message_bytes")}
    if any(value < 1 for value in parameters.values()):
        parser.error("all counts/sizes must be positive")
    args.bin_dir, args.web_root, args.config_template = (
        item.resolve() for item in (args.bin_dir, args.web_root, args.config_template))
    parameters.update(config_template_sha256=sha256(args.config_template),
                      max_connections=128, log_level="error", connection_mode="new connection per operation",
                      tls=False, workload_model="closed loop; fixed concurrency; no coordinated-omission correction")
    binaries = {}
    for service in SERVICES:
        binary = args.bin_dir / ("postplus-" + service + (".exe" if os.name == "nt" else ""))
        binaries[binary.name] = {"sha256": sha256(binary), "bytes": binary.stat().st_size}
    result = {
        "schema_version": 2, "status": "running", "label": args.label,
        "harness_sha256": {name: sha256(ROOT / name) for name in HARNESS_FILES},
        "source_revision": args.source_revision,
        "started_at_utc": datetime.now(timezone.utc).isoformat(), "parameters": parameters,
        "host": {"platform": platform.platform(), "machine": platform.machine(),
                 "processor": platform.processor(), "logical_cpus": os.cpu_count(),
                 "python": platform.python_version()},
        "binary_directory": str(args.bin_dir), "binaries": binaries,
        "limitations": ["Loopback cleartext network; not a WAN or TLS benchmark.",
                        "Client and server share a host; Python client can limit peak throughput.",
                        "Closed-loop results do not estimate overload or arrival-rate latency.",
                        "Latency includes client connect, protocol, response parsing and close.",
                        "SMTP timing includes QUIT after durable DATA acceptance; local delivery verified separately.",
                        "Server CPU/RSS exclude load generator and warmup; RSS sampled every 100 ms."],
        "rounds": [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def checkpoint():
        pending = args.output.with_name(args.output.name + ".partial.tmp")
        pending.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        pending.replace(args.output)

    checkpoint()
    try:
        for index in range(1, args.rounds + 1):
            partial = {}
            result["rounds"].append(partial)
            run_round(args, index, partial, checkpoint)
    except BaseException as error:
        result.update(status="failed", failure=f"{type(error).__name__}: {error}")
        checkpoint()
        raise
    result["summary"] = summarize(result["rounds"])
    result["status"] = "failed" if any(item["errors"] for item in result["summary"].values()) else "complete"
    result["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    checkpoint()
    print(json.dumps(result["summary"], indent=2), flush=True)
    if any(item["errors"] for item in result["summary"].values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
