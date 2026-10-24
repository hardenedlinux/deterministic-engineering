#!/usr/bin/env python3
"""Check declared source inputs and print an isolated Gerbil environment.

This is development preparation, not capture issuance or a build/load receipt.
No fetching, package removal, source editing or artifact fallback occurs here.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = Path(os.environ.get("FORMATION_DEPENDENCIES", ROOT / ".data/formation-dependencies")).resolve()
COHORT = Path(os.environ.get("FORMATION_COHORT", ROOT / ".data/formation-current")).resolve()


def git(source, *args, env=None):
    return subprocess.run(["git", "-C", str(source), *args], env=env,
                          check=True, capture_output=True, text=True).stdout


def checked_source(repository, directory, patch=None):
    matches = re.findall(r'"github\.com/tao3k/' + re.escape(repository) + r'@([0-9a-f]{40})"',
                         (ROOT / "gerbil.pkg").read_text())
    if len(matches) != 1:
        raise RuntimeError(f"one exact native dependency declaration required: {repository}")
    source = DEPENDENCIES / directory
    if git(source, "rev-parse", "HEAD").strip() != matches[0]:
        raise RuntimeError(f"checkout differs from gerbil.pkg: {source}")
    # A private index describes precisely the reviewed development patch. It
    # neither stages the user's checkout nor accepts unrelated source changes.
    with tempfile.TemporaryDirectory(prefix="formation-source-") as temporary:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(temporary) / "index"))
        git(source, "read-tree", "HEAD", env=env)
        if patch:
            git(source, "apply", "--cached", str(ROOT / "dev/patches" / patch), env=env)
        git(source, "diff", "--exit-code", env=env)
        if git(source, "ls-files", "--others", "--exclude-standard", env=env).strip():
            raise RuntimeError(f"unexpected untracked dependency inputs: {source}")
        files = git(source, "ls-files", "--stage", env=env).splitlines()
    digest = hashlib.sha256()
    gitlinks = []
    for entry in sorted(files):
        metadata, name = entry.split("\t", 1)
        mode, oid, stage = metadata.split()
        if stage != "0":
            raise RuntimeError(f"unmerged dependency input: {name}")
        path = source / name
        # An unselected gitlink is declared identity, never acquired source.
        # Consumers must independently acquire/check it before selecting it.
        if mode == "160000":
            data = ("unselected-gitlink:" + oid).encode()
            gitlinks.append({"path": name, "declaredCommit": oid, "status": "unselected"})
        elif mode == "120000":
            data = os.readlink(path).encode()
        else:
            data = path.read_bytes()
        digest.update(name.encode() + b"\0" + mode.encode() + b"\0" + data + b"\0")
    return source, {"repository": repository, "base": matches[0],
                    "source": str(source), "patch": patch, "treeSha256": digest.hexdigest(),
                    "unselectedGitlinks": gitlinks}


def mount(target, source):
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        if target.resolve() != source.resolve():
            raise RuntimeError(f"existing source mount differs: {target}")
    else:
        target.symlink_to(source, target_is_directory=True)


def main():
    tool_path = os.environ.get("FORMATION_TOOL_PATH", os.environ["PATH"])
    if "FORMATION_TOOL_PATH" in os.environ and any(
            not part or not Path(part).is_absolute() or not Path(part).is_dir()
            for part in tool_path.split(os.pathsep)):
        raise RuntimeError("tool search path requires existing absolute directories")
    core, core_record = checked_source("gebril-yuanxu", "yuanxu", "yuanxu-scope-and-build-roots.patch")
    ascent, ascent_record = checked_source("gerbil-ascent", "gerbil-ascent", "ascent-core-dependency.patch")
    context_records = []
    if os.environ.get("FORMATION_WITH_CONTEXT") == "1":
        flow, flow_record = checked_source("agentic-ai-lab", "agentic-ai-lab", "agentic-context-dependencies.patch")
        mount(COHORT / "source/agentic-ai-lab", flow)
        context_records.append(flow_record)
    poo, poo_record = checked_source("gerbil-poo", "gerbil-poo")
    mount(COHORT / "source/yuanxu", core)
    mount(COHORT / "source/tao3k/yuanxu", core)
    mount(COHORT / "source/gerbil-ascent", ascent)
    mount(COHORT / "source/clan/poo", poo)
    runtime = COHORT / "runtime"
    (runtime / "bin").mkdir(parents=True, exist_ok=True)
    COHORT.mkdir(parents=True, exist_ok=True)
    (COHORT / "source-baseline.json").write_text(json.dumps({
        "meaning": "checked development source preparation; not C or execution evidence",
        "dependencies": [core_record, ascent_record, poo_record] + context_records,
        "project": str(ROOT),
        "toolSearchPath": tool_path,
        "toolResolution": {name: shutil.which(name, path=tool_path)
                           for name in ("gxi", "gsc", "gcc", "ld", "pkg-config")},
    }, indent=2) + "\n")
    for key, value in {"GERBIL_PATH": str(runtime), "GERBIL_LOADPATH": str(COHORT / "source"),
                       "PATH": str(runtime / "bin") + os.pathsep + tool_path}.items():
        print(f"export {key}={shlex.quote(value)}")


if __name__ == "__main__":
    main()
