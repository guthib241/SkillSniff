#!/usr/bin/env python3
"""Scan ClawHub's development rows, to develop a rule change against them.

ClawHub's ``train`` and ``validation`` splits are this project's development
data (docs/EXTERNAL_VALIDATION.md, pre-registration 2): rules may be changed
against them, and no figure from them is a measurement. This scans every row
and records its verdict, the rules that fired, and the evidence of chosen
rules, so a change can be compared before and after on the same rows:

    python scripts/clawhub_dev_scan.py --src /path/to/old/src --jsonl train.jsonl validation.jsonl \\
        --out before.jsonl --evidence EXE001,EXE002
    python scripts/clawhub_dev_scan.py --jsonl train.jsonl validation.jsonl \\
        --out after.jsonl --evidence EXE001,EXE002
    python scripts/clawhub_dev_scan.py --compare before.jsonl after.jsonl

The files are ``data/train.jsonl`` and ``data/validation.jsonl`` from
``OpenClaw/clawhub-security-signals`` at ``69dcbd323c155312fb000ec89ea0b1efdf6a5757``.
Rows are materialised as ``scripts/holdout_eval.py`` does it: the bundle's own
``SKILL.md`` when it has one, else ``skill_md_content``, which ClawHub stores
with its newlines removed. Each row is written to a fresh temporary directory,
every path checked, scanned, and deleted. Nothing is executed.

``--src`` imports SkillSniff from another source tree, so the "before" side can
be an exported copy of an earlier commit while the working tree changes.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parent.parent
SHARD_ROWS = 250
MAX_EXCERPTS = 5


# -- materialise, scan, delete: in worker processes ------------------------------------


def _init_worker(src: str) -> None:
    sys.path.insert(0, src)
    from skillsniff.engine import load_rules

    load_rules()


def _write(directory: Path, rel: PurePosixPath, content: str) -> None:
    target = directory.joinpath(*rel.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(target, flags, 0o600), "w", encoding="utf-8", errors="replace") as fh:
        fh.write(content)


def _materialise(row: dict, directory: Path) -> int:
    """Write the row's skill; return how many bundle entries were refused."""
    refused = 0
    wrote_entry = False
    seen: set[PurePosixPath] = set()
    for entry in row.get("skill_bundle_content") or []:
        if not isinstance(entry, dict) or not isinstance(entry.get("content"), str):
            continue
        raw = str(entry.get("path") or "")
        rel = PurePosixPath(raw)
        if (not rel.parts or rel.is_absolute() or ".." in rel.parts or "\\" in raw or "\x00" in raw
                or rel in seen or any(parent in seen for parent in rel.parents)):
            refused += 1
            continue
        try:
            _write(directory, rel, entry["content"])
        except OSError:  # a file where a directory is needed, and the like
            refused += 1
            continue
        seen.add(rel)
        wrote_entry = wrote_entry or str(rel) == "SKILL.md"
    if not wrote_entry:
        _write(directory, PurePosixPath("SKILL.md"), row.get("skill_md_content") or "")
    return refused


def scan_shard(task: tuple[str, str, int, int, int, list[str], str]) -> list[dict]:
    path, split, offset, first, count, evidence, workdir = task
    from skillsniff.core.config import Config
    from skillsniff.engine import scan

    out: list[dict] = []
    with open(path, "rb") as fh:
        fh.seek(offset)
        for number in range(first, first + count):
            row = json.loads(fh.readline())
            record: dict = {"split": split, "row": number, "id": row.get("id"),
                            "label": row.get("clawscan_verdict")}
            directory = Path(tempfile.mkdtemp(dir=workdir))
            try:
                record["refused_paths"] = _materialise(row, directory)
                result = scan(directory, Config())
                if not result.skills:
                    record.update(verdict="NO_SKILL", rules=[], evidence={})
                else:
                    skill = result.skills[0]
                    record["verdict"] = skill.risk.verdict.value
                    record["rules"] = sorted({f"{f.rule_id}:{f.severity.value}" for f in skill.findings})
                    record["evidence"] = {
                        rule: [f.message[:200] for f in skill.findings if f.rule_id == rule][:MAX_EXCERPTS]
                        for rule in evidence
                        if any(f.rule_id == rule for f in skill.findings)
                    }
            except Exception as exc:  # recorded, never hidden
                record.update(verdict="ERROR", error=f"{type(exc).__name__}: {exc}"[:300], rules=[], evidence={})
            finally:
                shutil.rmtree(directory, ignore_errors=True)
            out.append(record)
    return out


# -- sharding, so no worker holds more than a few hundred rows ---------------------------


def shards(path: Path, split: str, evidence: list[str], workdir: str) -> list[tuple]:
    starts: list[int] = []
    with path.open("rb") as fh:
        offset = 0
        for line in fh:
            starts.append(offset)
            offset += len(line)
    return [(str(path), split, starts[first], first, min(SHARD_ROWS, len(starts) - first), evidence, workdir)
            for first in range(0, len(starts), SHARD_ROWS)]


def run(args: argparse.Namespace) -> int:
    src = str(Path(args.src).resolve())
    evidence = [r for r in args.evidence.split(",") if r]
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="clawhub-dev-") as workdir:
        tasks: list[tuple] = []
        for path in args.jsonl:
            split = path.name.split(".")[0]
            tasks += shards(path, split, evidence, workdir)
        total = sum(t[4] for t in tasks)
        done = 0
        with args.out.open("w") as out, ProcessPoolExecutor(
            max_workers=args.workers, initializer=_init_worker, initargs=(src,)
        ) as pool:
            for records in pool.map(scan_shard, tasks):
                for record in records:
                    out.write(json.dumps(record) + "\n")
                done += len(records)
                print(f"  {done}/{total} in {time.monotonic() - started:.0f}s", file=sys.stderr)
    print(f"scanned {total} rows with {src} in {time.monotonic() - started:.0f}s -> {args.out}")
    return 0


# -- compare two runs -----------------------------------------------------------------------


def compare(before_path: Path, after_path: Path, rules: list[str]) -> int:
    def load(path: Path) -> dict[tuple[str, int], dict]:
        with path.open() as fh:
            return {(r["split"], r["row"]): r for r in map(json.loads, fh)}

    before, after = load(before_path), load(after_path)
    if before.keys() != after.keys():
        raise SystemExit("the two runs did not scan the same rows")
    moves: Counter[tuple[str, str, str]] = Counter()
    for key, old in before.items():
        new = after[key]
        if old["verdict"] != new["verdict"]:
            moves[(str(old["label"]), old["verdict"], new["verdict"])] += 1
    print(f"{len(before)} rows; verdict changes by ClawScan label:")
    for (label, old, new), count in sorted(moves.items()):
        print(f"  {label:10} {old:12} -> {new:12} {count}")
    if not moves:
        print("  none")
    for rule in rules:
        lost = [(k, before[k]) for k in before if rule in before[k]["evidence"] and rule not in after[k]["evidence"]]
        gained = [(k, after[k]) for k in after if rule in after[k]["evidence"] and rule not in before[k]["evidence"]]
        fired = sum(rule in r["evidence"] for r in before.values())
        print(f"\n{rule}: fired on {fired} rows before; lost on {len(lost)}, gained on {len(gained)}")
        for (split, row), record in lost:
            print(f"  - {split}-{row:05d} [{record['label']}] {after[(split, row)]['verdict']}: "
                  + " | ".join(record["evidence"][rule])[:300])
        for (split, row), record in gained:
            print(f"  + {split}-{row:05d} [{record['label']}]: " + " | ".join(record["evidence"][rule])[:300])
    errors = [k for k, r in after.items() if r["verdict"] == "ERROR"]
    print(f"\nscans that raised: before {sum(r['verdict'] == 'ERROR' for r in before.values())}, after {len(errors)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--jsonl", type=Path, nargs="*", default=[], help="ClawHub train/validation JSONL files")
    parser.add_argument("--out", type=Path, help="where to write one JSON record per row")
    parser.add_argument("--src", default=str(REPO_ROOT / "src"), help="the SkillSniff source tree to import")
    parser.add_argument("--evidence", default="", help="comma-separated rules whose evidence to record")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 2)
    parser.add_argument("--compare", type=Path, nargs=2, metavar=("BEFORE", "AFTER"))
    args = parser.parse_args()
    if args.compare:
        return compare(*args.compare, [r for r in args.evidence.split(",") if r] or ["EXE001", "EXE002"])
    if not args.jsonl or not args.out:
        parser.error("--jsonl and --out are required to scan")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
