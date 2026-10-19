"""Provenance verifier: is the autopilot-kit tree at SHA exactly the render of kit/ at autopilot commit C?

Read-only and stdlib-only. It never imports or runs code from C: it parses C's cli.py with `ast`, pulls the pinned action
SHAs and KIT_README out as literals, reads kit/workflows/*.yml and kit/runtime/*.py from C, and applies its OWN copy of the
export logic (`render_kit`). If C's export_kit/render source is not one this module knows (KNOWN_EXPORT_HASHES), it fails closed.

Everything is REST (git trees, git blobs, compare). The HTTP opener is injected
(`opener(url) -> (status, body_bytes)`) and resolved at call time, so tests substitute a fake.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping

API = "https://api.github.com"
HEX40 = re.compile(r"[0-9a-f]{40}")
PIN_NAMES = ("CHECKOUT_SHA", "SETUP_NODE_SHA", "ACTION_SHA")  # the *_SHA constants export_kit substitutes
CLI_PATH = "src/autopilot/cli.py"

# sha256 over the source text of C's `render` and `export_kit` (see export_hash). BUMP WHEN THE EXPORT FORMAT CHANGES: any
# edit to those two functions in src/autopilot/cli.py (a new substitution, a new input dir, a changed mode) must be mirrored
# in render_kit below and then the new hash added here. A hash this module does not know fails closed.
KNOWN_EXPORT_HASHES = frozenset(
    {
        "bc29f868f9c0a92a5c92165a7da94080893d9c33ca300e765d1ef95af1f33c2d",  # before #50: export_kit(dest)
        "5baf7dee46744931f22d80c9005a0577eba019375d4541836c548bf010cf86e6",  # #50: adds the optional `kit` root; output unchanged
    }
)

# Verifier's own copy; never taken from C, so a hostile commit cannot weaken it.
KIT_FORBIDDEN = [r"RyanJHamby", r"ryanhamby", r"/Users/", r"sk-ant-oat\d*-[A-Za-z0-9_-]{16,}", r"@gmail", r"ampentra"]

Opener = Callable[[str], "tuple[int, bytes]"]


class ProvenanceError(Exception):
    """Any reason to refuse. Always fails closed."""


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324 (git object id, not security hashing)


def render(data: bytes, subs: Mapping[str, str]) -> bytes:
    """Plain {{K}} replace over bytes, in the order given (same semantics as cli.render)."""
    for k, v in subs.items():
        data = data.replace(b"{{" + k.encode() + b"}}", v.encode())
    return data


def render_kit(
    readme: str, workflows: Mapping[str, bytes], runtime: Mapping[str, bytes], pins: Mapping[str, str]
) -> dict[str, bytes]:
    """The verifier's own export: path -> bytes of the public kit tree. Sorted inputs; no clock, env or locale."""
    subs = {"CHECKOUT_SHA": pins["CHECKOUT_SHA"], "ACTION_SHA": pins["ACTION_SHA"], "SETUP_NODE_SHA": pins["SETUP_NODE_SHA"]}
    files: dict[str, bytes] = {"README.md": readme.encode()}
    for name in sorted(workflows):
        files[f".github/workflows/{name}"] = render(workflows[name], subs)
    for name in sorted(runtime):
        files[f"runtime/{name}"] = runtime[name]
    for rel in sorted(files):
        if b"\r" in files[rel]:
            raise ProvenanceError(f"{rel}: carriage return in kit input (export newline handling is not modelled)")
        text = files[rel].decode()
        for bad in KIT_FORBIDDEN:
            if re.search(bad, text):
                raise ProvenanceError(f"{rel}: rendered output matches forbidden pattern {bad!r}")
    return files


# --- reading C without running it -------------------------------------------------------------------------------------


def export_hash(cli_text: str) -> str:
    """sha256 of the source text of the module-level `render` and `export_kit` functions in C's cli.py."""
    tree = ast.parse(cli_text)
    parts = []
    for name in ("render", "export_kit"):
        defs = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name]
        if len(defs) != 1 or defs[0].decorator_list:
            raise ProvenanceError(f"cli.py must define exactly one undecorated top-level {name}()")
        rebound = [
            n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)
        ]
        if rebound:
            raise ProvenanceError(f"cli.py rebinds {name}")
        seg = ast.get_source_segment(cli_text, defs[0])
        if seg is None:
            raise ProvenanceError(f"cannot read source of {name}()")
        parts.append(name + "\n" + seg)
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def extract_constants(cli_text: str) -> tuple[dict[str, str], str]:
    """(pins, KIT_README) from top-level literal assignments in C's cli.py. Missing, duplicated or non-literal -> refuse."""
    tree = ast.parse(cli_text)
    found: dict[str, object] = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            name = n.targets[0].id
            if name in PIN_NAMES or name == "KIT_README":
                if name in found:
                    raise ProvenanceError(f"{name} assigned more than once in cli.py")
                try:
                    found[name] = ast.literal_eval(n.value)
                except (ValueError, SyntaxError) as e:
                    raise ProvenanceError(f"{name} is not a literal: {e}") from e
    pins: dict[str, str] = {}
    for name in PIN_NAMES:
        v = found.get(name)
        if not isinstance(v, str) or not HEX40.fullmatch(v):
            raise ProvenanceError(f"{name} missing or not 40 lowercase hex in cli.py")
        pins[name] = v
    readme = found.get("KIT_README")
    if not isinstance(readme, str):
        raise ProvenanceError("KIT_README missing or not a string literal in cli.py")
    return pins, readme


# --- GitHub (REST only, injected opener) --------------------------------------------------------------------------------


def _default_opener(url: str) -> tuple[int, bytes]:
    h = {"Accept": "application/vnd.github.raw+json", "User-Agent": "autopilot-provenance"}
    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=20) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


def _get(opener: Opener, url: str) -> bytes:
    status, body = opener(url)
    if status != 200:
        raise ProvenanceError(f"GET {url} -> HTTP {status}")
    return body


def _get_json(opener: Opener, url: str) -> dict:
    try:
        j = json.loads(_get(opener, url))
    except ValueError as e:
        raise ProvenanceError(f"GET {url}: invalid JSON") from e
    if not isinstance(j, dict):
        raise ProvenanceError(f"GET {url}: unexpected JSON shape")
    return j


def _tree(opener: Opener, repo: str, sha: str) -> dict[str, tuple[str, str]]:
    """path -> (mode, blob sha) for every non-directory entry. Refuses a truncated or malformed listing."""
    j = _get_json(opener, f"{API}/repos/{repo}/git/trees/{sha}?recursive=1")
    if j.get("truncated") is not False or not isinstance(j.get("tree"), list):
        raise ProvenanceError(f"tree of {repo}@{sha[:7]} is truncated or malformed")
    out: dict[str, tuple[str, str]] = {}
    for e in j["tree"]:
        if not isinstance(e, dict) or not all(isinstance(e.get(k), str) for k in ("path", "mode", "type", "sha")):
            raise ProvenanceError(f"tree of {repo}@{sha[:7]}: malformed entry")
        if e["type"] == "tree":
            continue
        if e["path"] in out:
            raise ProvenanceError(f"tree of {repo}@{sha[:7]}: duplicate path {e['path']}")
        out[e["path"]] = (e["mode"], e["sha"])
    return out


def _source_blob(opener: Opener, repo: str, tree: Mapping[str, tuple[str, str]], path: str) -> bytes:
    if path not in tree:
        raise ProvenanceError(f"{path} not in source commit")
    mode, sha = tree[path]
    if mode not in ("100644", "100755"):
        raise ProvenanceError(f"{path}: unexpected mode {mode}")
    data = _get(opener, f"{API}/repos/{repo}/git/blobs/{sha}")
    if blob_sha(data) != sha:
        raise ProvenanceError(f"{path}: fetched bytes do not hash to the tree's blob {sha[:7]}")
    return data


def _ancestor(opener: Opener, repo: str, older: str, newer: str) -> bool:
    """True iff `older` is `newer` or an ancestor of it.

    GET /compare/{base}...{head} reports `status` of HEAD relative to BASE: 'ahead' (head has commits base lacks and base is an
    ancestor of head), 'identical', 'behind' (head is an ancestor of base), 'diverged'. With base=older, head=newer, the answer
    is yes exactly for 'ahead' or 'identical'. ('behind' means newer is OLDER than `older`; 'diverged' means unrelated lines.)"""
    j = _get_json(opener, f"{API}/repos/{repo}/compare/{older}...{newer}?per_page=1")
    return j.get("status") in ("ahead", "identical")


# --- the checks --------------------------------------------------------------------------------------------------------


def parse_source_hint(approved_text: str, kit_sha: str) -> str:
    """The autopilot commit recorded as `source=<40-hex>` on the kit sha's APPROVED line. Exactly one, else refuse."""
    lines = [ln for ln in approved_text.splitlines() if ln.split(None, 1)[:1] == [kit_sha]]
    if len(lines) != 1:
        raise ProvenanceError(f"APPROVED has {len(lines)} lines for {kit_sha[:7]}; need exactly 1")
    hints = [t[len("source=") :] for t in lines[0].split()[1:] if t.startswith("source=")]
    if len(hints) != 1 or not HEX40.fullmatch(hints[0]):
        raise ProvenanceError("APPROVED line has no single well-formed source=<40-hex> hint")
    return hints[0]


def verify_approved_diff(old_text: str, new_text: str) -> list[str]:
    """Problems with a change to APPROVED: the only allowed edit is adding lines `<40-hex>[ note]`. Empty list = fine."""
    old = old_text.removesuffix("\n").split("\n") if old_text else []
    new = new_text.removesuffix("\n").split("\n") if new_text else []
    bad: list[str] = []
    seen = {ln.split()[0] for ln in old if HEX40.match(ln)}
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=old, b=new, autojunk=False).get_opcodes():
        if tag in ("delete", "replace"):
            bad.append(f"removed or changed: {old[i1:i2]!r}")
        if tag in ("insert", "replace"):
            for ln in new[j1:j2]:
                if not re.fullmatch(r"[0-9a-f]{40}(?: [ -~]*)?", ln):
                    bad.append(f"added line is not '<40-hex>[ note]': {ln!r}")
                elif ln[:40] in seen:
                    bad.append(f"sha {ln[:7]} is already approved")
                else:
                    seen.add(ln[:40])
    return bad


def verify_export(actual: Mapping[str, tuple[str, str]], rendered: Mapping[str, bytes]) -> list[str]:
    """Exact set equality of (path, mode 100644, blob sha). Returns every difference."""
    want = {p: ("100644", blob_sha(b)) for p, b in rendered.items()}
    bad = []
    for p in sorted(set(want) - set(actual)):
        bad.append(f"missing from kit: {p}")
    for p in sorted(set(actual) - set(want)):
        bad.append(f"extra in kit: {p}")
    for p in sorted(set(want) & set(actual)):
        if actual[p] != want[p]:
            bad.append(f"{p}: kit has mode/blob {actual[p]}, expected {want[p]}")
    return bad


def default_source_repo(kit_repo: str) -> str:
    return kit_repo.split("/")[0] + "/autopilot"


def verify_provenance(
    kit_repo: str,
    kit_sha: str,
    source_sha: str,
    pins: Mapping[str, str],
    *,
    previous_source: str | None = None,
    source_repo: str | None = None,
    main_branch: str = "main",
    opener: Opener | None = None,
) -> list[str]:
    """Reasons the kit at kit_sha is NOT the render of source_repo@source_sha (empty list = verified). Fails closed."""
    opener = opener or _default_opener  # bound at call time
    try:
        return _verify(kit_repo, kit_sha, source_sha, pins, previous_source, source_repo, main_branch, opener)
    except ProvenanceError as e:
        return [str(e)]
    except Exception as e:  # noqa: BLE001 - anything unexpected is a refusal, never a pass
        return [f"unexpected {type(e).__name__}: {e}"]


def _verify(kit_repo, kit_sha, source_sha, pins, previous_source, source_repo, main_branch, opener) -> list[str]:
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", kit_repo or ""):
        raise ProvenanceError("kit repo must look like OWNER/REPO")
    for label, s in (("kit sha", kit_sha), ("source sha", source_sha)):
        if not isinstance(s, str) or not HEX40.fullmatch(s):
            raise ProvenanceError(f"{label} must be 40 lowercase hex")
    if previous_source is not None and not HEX40.fullmatch(previous_source):
        raise ProvenanceError("previous source must be 40 lowercase hex")
    src = source_repo or default_source_repo(kit_repo)

    if not _ancestor(opener, src, source_sha, main_branch):
        raise ProvenanceError(f"{source_sha[:7]} is not reachable from {src}@{main_branch}")
    if previous_source is not None and not _ancestor(opener, src, previous_source, source_sha):
        raise ProvenanceError(f"rollback: previous approved source {previous_source[:7]} is not an ancestor of {source_sha[:7]}")

    tree = _tree(opener, src, source_sha)
    cli_text = _source_blob(opener, src, tree, CLI_PATH).decode()
    if export_hash(cli_text) not in KNOWN_EXPORT_HASHES:
        raise ProvenanceError("export_kit/render at the source commit is not a known export format (bump KNOWN_EXPORT_HASHES)")
    c_pins, readme = extract_constants(cli_text)
    if dict(pins) != c_pins:
        raise ProvenanceError(f"pins differ from the approved pins: source has {c_pins}, approved {dict(pins)}")

    def group(prefix: str, suffix: str) -> dict[str, bytes]:
        names = [p for p in sorted(tree) if p.startswith(prefix) and "/" not in p[len(prefix) :] and p.endswith(suffix)]
        return {p[len(prefix) :]: _source_blob(opener, src, tree, p) for p in names}

    rendered = render_kit(readme, group("kit/workflows/", ".yml"), group("kit/runtime/", ".py"), c_pins)
    bad = verify_export(_tree(opener, kit_repo, kit_sha), rendered)
    if bad:
        raise ProvenanceError("kit tree differs from the render:\n  " + "\n  ".join(bad))
    return []
