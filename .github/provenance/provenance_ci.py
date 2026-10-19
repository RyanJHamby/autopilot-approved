"""CI glue for the required `provenance` check on <owner>/autopilot-approved.

Deployed next to provenance.py (both copied into the approvals repo's .github/provenance/) and run by a pull_request_target
workflow from the BASE branch. The PR's APPROVED is fetched as DATA over REST; PR code is never checked out or executed.

A PR passes only if it changes nothing but APPROVED, adds nothing but `<40-hex>[ note]` lines, and every added kit sha is
proven by provenance.verify_provenance to be the render of an autopilot commit on main. Everything fails closed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

try:
    from autopilot import provenance as prov
except ImportError:  # deployed beside provenance.py; `python3 -I` drops the script dir from sys.path, so add it explicitly
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import provenance as prov  # type: ignore[no-redef]

APPROVED_FILE = "APPROVED"
FILES_PAGE = 100
FILES_API_LIMIT = 3000  # GitHub lists at most 3000 changed files; at the limit the list may be incomplete
REPO = re.compile(r"[\w.-]+/[\w.-]+")


def _line_source(line: str) -> str | None:
    """The well-formed source=<40-hex> on an APPROVED line, if it has exactly one."""
    hints = [t[len("source=") :] for t in line.split()[1:] if t.startswith("source=")]
    return hints[0] if len(hints) == 1 and prov.HEX40.fullmatch(hints[0]) else None


def _approved_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if prov.HEX40.match(ln)]


def check_pr(
    base_approved: str,
    head_approved: str,
    changed_files: list[str],
    pins: Mapping[str, str],
    kit_repo: str,
    source_repo: str | None = None,
    opener: Callable | None = None,
) -> list[str]:
    """Reasons this PR must not satisfy the check (empty list = pass)."""
    if changed_files != [APPROVED_FILE]:
        return [
            f"PR changes {sorted(set(changed_files)) or 'no files'}; only {APPROVED_FILE} may change (anything else needs owner review)"
        ]
    bad = prov.verify_approved_diff(base_approved, head_approved)
    if bad:
        return bad
    base_lines = set(base_approved.splitlines())
    added = [ln for ln in head_approved.splitlines() if ln not in base_lines and ln.strip()]
    if not added:
        return ["PR adds no approval line: nothing to verify"]

    previous = next((s for s in (_line_source(ln) for ln in reversed(_approved_lines(base_approved))) if s), None)
    problems: list[str] = []
    for ln in added:
        kit_sha = ln[:40]
        try:
            source = prov.parse_source_hint(head_approved, kit_sha)
        except prov.ProvenanceError as e:
            problems.append(f"{kit_sha[:7]}: {e}")
            continue
        found = prov.verify_provenance(
            kit_repo, kit_sha, source, pins, previous_source=previous, source_repo=source_repo, opener=opener
        )
        problems += [f"{kit_sha[:7]}: {p}" for p in found]
        previous = source  # the next line in this PR must descend from this one
    return problems


# --- fetching (REST only; the PR's content is data) ---------------------------------------------------------------------


def changed_files(opener: Callable, repo: str, number: int) -> list[str]:
    """Every path the PR touches (renames list both names). Fails closed on an API error or a possibly truncated list."""
    out: list[str] = []
    page = 1
    while True:
        status, body = opener(f"{prov.API}/repos/{repo}/pulls/{number}/files?per_page={FILES_PAGE}&page={page}")
        if status != 200:
            raise prov.ProvenanceError(f"pulls/{number}/files -> HTTP {status}")
        try:
            items = json.loads(body)
        except ValueError as e:
            raise prov.ProvenanceError("pulls files: invalid JSON") from e
        if not isinstance(items, list) or not all(isinstance(i, dict) and isinstance(i.get("filename"), str) for i in items):
            raise prov.ProvenanceError("pulls files: unexpected shape")
        for i in items:
            out.append(i["filename"])
            if isinstance(i.get("previous_filename"), str):
                out.append(i["previous_filename"])
        if len(out) >= FILES_API_LIMIT:
            raise prov.ProvenanceError("PR file list may be truncated")
        if len(items) < FILES_PAGE:
            return out
        page += 1


def head_approved(opener: Callable, head_repo: str, head_sha: str) -> str:
    if not REPO.fullmatch(head_repo or "") or not prov.HEX40.fullmatch(head_sha or ""):
        raise prov.ProvenanceError("PR head repo/sha malformed")
    return prov._get(opener, f"{prov.API}/repos/{head_repo}/contents/{APPROVED_FILE}?ref={head_sha}").decode()


def _load_pins(path: str) -> dict[str, str]:
    pins = json.loads(Path(path).read_text())
    if not isinstance(pins, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in pins.items()):
        raise prov.ProvenanceError("pins.json must map names to strings")
    return pins


def main(argv: list[str] | None = None, opener: Callable | None = None) -> int:
    ap = argparse.ArgumentParser(prog="provenance_ci")
    ap.add_argument("--pins", required=True, help="approved pins.json from the BASE checkout")
    ap.add_argument("--approved", default=APPROVED_FILE, help="APPROVED from the BASE checkout")
    ns = ap.parse_args(argv)
    opener = opener or prov._default_opener  # bound at call time
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        pr = event["pull_request"]
        number, head = int(pr["number"]), pr["head"]
        repo = os.environ["GITHUB_REPOSITORY"]
        if not REPO.fullmatch(repo):
            raise prov.ProvenanceError("GITHUB_REPOSITORY malformed")
        owner = repo.split("/")[0]
        problems = check_pr(
            Path(ns.approved).read_text(),
            head_approved(opener, head["repo"]["full_name"], head["sha"]),
            changed_files(opener, repo, number),
            _load_pins(ns.pins),
            f"{owner}/autopilot-kit",
            f"{owner}/autopilot",
            opener,
        )
    except (prov.ProvenanceError, KeyError, TypeError, ValueError, OSError) as e:
        problems = [f"{type(e).__name__}: {e}"]
    for p in problems:
        print(f"FAIL {p}", file=sys.stderr)
    if not problems:
        print("PASS every added kit sha is the render of an autopilot commit on main")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
