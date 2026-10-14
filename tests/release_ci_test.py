#!/usr/bin/env python3
"""Offline regression checks for the release's exact-commit CI safety gate."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from release_ci import branch_run, verify_branch_ci

SHA = "a" * 40


def run_record(**changes):
    return {"id": 42, "event": "push", "head_sha": SHA, "head_branch": "main",
            "status": "completed", "conclusion": "success", **changes}


class FakeClock:
    def __init__(self):
        self.elapsed = 0

    def now(self):
        return self.elapsed

    def sleep(self, seconds):
        self.elapsed += seconds


class ReleaseCiTest(unittest.TestCase):
    def verify(self, responses, **kwargs):
        clock = FakeClock()
        paths = []
        replies = iter(responses)

        def get(path):
            paths.append(path)
            return next(replies)

        result = verify_branch_ci(get, SHA, discovery_seconds=2, wait_seconds=3,
                                  poll_seconds=1, now=clock.now, sleep=clock.sleep,
                                  log=lambda _: None, **kwargs)
        return result, paths, clock.elapsed

    def test_only_exact_commit_branch_push_can_be_reused(self):
        payload = {"workflow_runs": [
            run_record(id=100, head_sha="b" * 40),
            run_record(id=101, event="pull_request"),
            run_record(id=102, event="workflow_dispatch"),
            run_record(id=103, head_branch=None),
            run_record(id="104"), run_record(),
        ]}
        result, paths, elapsed = self.verify([payload])
        self.assertEqual(result["id"], 42)
        self.assertIn("head_sha=" + SHA, paths[0])
        self.assertEqual(elapsed, 0)

    def test_newest_branch_push_run_wins(self):
        self.assertEqual(branch_run({"workflow_runs": [run_record(id=1), run_record(id=2)]}, SHA)["id"], 2)

    def test_absent_branch_run_uses_complete_fallback(self):
        result, paths, elapsed = self.verify([{"workflow_runs": []}] * 3)
        self.assertIsNone(result)
        self.assertEqual(len(paths), 3)
        self.assertEqual(elapsed, 2)

    def test_simultaneous_push_run_can_appear_after_release_starts(self):
        result, paths, elapsed = self.verify([
            {"workflow_runs": []},
            {"workflow_runs": [run_record(status="queued", conclusion=None)]},
            run_record(status="in_progress", conclusion=None), run_record(),
        ])
        self.assertEqual(result["id"], 42)
        self.assertEqual(paths[-2:], ["actions/runs/42"] * 2)
        self.assertEqual(elapsed, 3)

    def test_unsuccessful_branch_ci_blocks_publication_without_fallback(self):
        for conclusion in ("failure", "cancelled", "timed_out", "action_required", "skipped", None):
            with self.subTest(conclusion=conclusion), self.assertRaisesRegex(RuntimeError, "before publishing"):
                self.verify([{"workflow_runs": [run_record(conclusion=conclusion)]}])

    def test_failure_after_wait_also_blocks(self):
        with self.assertRaisesRegex(RuntimeError, "concluded failure"):
            self.verify([{"workflow_runs": [run_record(status="in_progress", conclusion=None)]},
                         run_record(conclusion="failure")])

    def test_wait_for_incomplete_ci_is_bounded(self):
        pending = run_record(status="in_progress", conclusion=None)
        with self.assertRaises(TimeoutError):
            self.verify([{"workflow_runs": [pending]}] + [pending] * 3)

    def test_changed_commit_cannot_be_accepted_while_polling(self):
        with self.assertRaisesRegex(RuntimeError, "no longer identifies"):
            self.verify([{"workflow_runs": [run_record(status="in_progress", conclusion=None)]},
                         run_record(head_sha="b" * 40)])

    def test_api_errors_do_not_bypass_ci(self):
        def unavailable(_):
            raise OSError("API unavailable")

        with self.assertRaises(OSError):
            verify_branch_ci(unavailable, SHA)


if __name__ == "__main__":
    unittest.main()
