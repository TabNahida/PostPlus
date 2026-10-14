#!/usr/bin/env python3
"""Reuse the exact commit's branch CI, or request a complete release CI run.

Only branch-push runs of ci.yml qualify. A missing run uses the reusable CI;
a failed/cancelled run or an API error blocks publication instead of silently
falling back and hiding a failed check. This workflow never waits on itself.
"""
import json
import os
import re
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def branch_run(payload, sha):
    runs = [run for run in payload["workflow_runs"]
            if run.get("head_sha") == sha and run.get("event") == "push"
            and run.get("head_branch") and isinstance(run.get("id"), int)]
    return max(runs, key=lambda run: run["id"], default=None)


def verify_branch_ci(get, sha, *, discovery_seconds=60, wait_seconds=2700,
                     poll_seconds=15, now=time.monotonic, sleep=time.sleep,
                     log=print):
    """Return a successful run, or None if no branch CI exists for this SHA."""
    endpoint = "actions/workflows/ci.yml/runs?" + urlencode({
        "head_sha": sha, "event": "push", "per_page": 100,
    })
    discovery_deadline = now() + discovery_seconds
    while True:
        run = branch_run(get(endpoint), sha)
        if run is not None:
            break
        remaining = discovery_deadline - now()
        if remaining <= 0:
            log("No branch CI for this commit; running the complete six-job test matrix.")
            return None
        sleep(min(poll_seconds, remaining))

    log(f"Waiting for branch CI {run['id']} on {sha}.")
    wait_deadline = now() + wait_seconds
    while True:
        if run.get("head_sha") != sha or run.get("event") != "push":
            raise RuntimeError("The selected branch CI no longer identifies the release commit")
        if run.get("status") == "completed":
            if run.get("conclusion") != "success":
                raise RuntimeError(f"Branch CI {run['id']} concluded {run.get('conclusion')}; "
                                   "fix or rerun that check before publishing")
            log(f"Verified successful branch CI {run['id']}; no duplicate matrix is needed.")
            return run
        remaining = wait_deadline - now()
        if remaining <= 0:
            raise TimeoutError(f"Branch CI {run['id']} did not finish within {wait_seconds} seconds")
        sleep(min(poll_seconds, remaining))
        run = get(f"actions/runs/{run['id']}")


def main():
    repository = os.environ["GITHUB_REPOSITORY"]
    sha = os.environ["GITHUB_SHA"]
    token = os.environ["GH_TOKEN"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid repository")
    if not re.fullmatch(r"[0-9a-f]{40,64}", sha):
        raise ValueError("Invalid commit SHA")

    def get(path):
        request = Request(f"https://api.github.com/repos/{repository}/{path}", headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "PostPlus-release-ci",
        })
        with urlopen(request, timeout=30) as response:
            return json.load(response)

    run = verify_branch_ci(get, sha)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"reused={'true' if run else 'false'}\n")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        if run:
            url = f"https://github.com/{repository}/actions/runs/{run['id']}"
            summary.write(f"Reused successful [branch CI]({url}) for `{sha}`. "
                          "All six platform/build-mode jobs passed.\n")
        else:
            summary.write("No branch CI found for this exact commit. "
                          "The release runs the complete six-job CI matrix.\n")


if __name__ == "__main__":
    main()
