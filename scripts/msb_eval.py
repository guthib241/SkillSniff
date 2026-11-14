#!/usr/bin/env python3
"""Pre-registration 3: SkillSniff on MaliciousSkillBench's source-disjoint test split.

Implements the protocol fixed in docs/EXTERNAL_VALIDATION.md before any
MaliciousSkillBench sample was downloaded:

* ``ProtectSkills/MaliciousSkillBench`` at the revision Cisco's skill-scanner
  pins, each file checked against the size and SHA-256 that harness pins.
* Split ``source_disjoint``, members marked ``test``: 1,384 identities (839
  malicious, 545 benign) from the held-out sources SRC009, SRC011 and SRC012.
* Each identity's ``skill_text`` -- or ``public_skill_text`` where the exact
  text is withheld -- written as a skill's ``SKILL.md``, UTF-8 with no newline
  translation, as Cisco's harness materialises it.
* Three operating points: BLOCK; BLOCK or REVIEW; BLOCK, REVIEW or CAUTION.
  INCONCLUSIVE, a scan that raises, and a directory with no skill count as
  not detected.
* Recall, false-positive rate, precision and F1 with Wilson 95% intervals,
  compared with Cisco's published figures at matched false-positive rate.

Added after the pre-registration commit and the download, before any sample
was scanned: an overlap audit. Every test identity's text, whitespace removed,
is hashed and compared with the ClawHub development rows this project fixed
false positives against (``--clawhub-dev``) and with every ``SKILL.md`` in this
repository, both exactly and by the first 300 non-whitespace characters. If any
identity overlaps, every figure is also reported without the overlapping ones.

Nothing is executed and no URL in a sample is followed. Reading Parquet needs
``pyarrow``; that is the evaluation's dependency, not the scanner's, which
stays stdlib-only. MaliciousSkillBench's own metadata is CC-BY-4.0; only
identifiers, labels and this tool's verdicts are written out.

    python scripts/msb_eval.py --cache ~/.cache/skillsniff-msb --out docs/results/msb-2026-11-14 \\
        --clawhub-dev ~/.cache/clawhub/train.jsonl ~/.cache/clawhub/validation.jsonl
    python scripts/msb_eval.py --render docs/results/msb-2026-11-14/summary.json
    python scripts/msb_eval.py --overlap-detail --cache ... --out ... --clawhub-dev ...

The run refuses to start unless ``src/`` is committed and identical to the
tree the pre-registration fixed, and refuses to overwrite an earlier result:
the split is scanned once.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Iterable
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from holdout_eval import _rate, fetch, resolve_url, scanned_commit  # noqa: E402

DATASET = "ProtectSkills/MaliciousSkillBench"
PIN = "d4b42ce5766a6e0359c987cf59c1007cb3795a90"
#: Size and SHA-256 of each file as Cisco's skill-scanner pins them
#: (evals/datasets/public-datasets.profile.json at c558c42).
FILES = {
    "primary.parquet": (28_600_360, "1d6382017f259bde0b699d402318f3c03f16b2e8ed2363a346b77a5465f06a06"),
    "splits/source_disjoint.parquet": (27_820, "9fae37c53b6ad47070d118e9bc4cdafd82c416a68b7e74847b4e0dd9d66bd276"),
}
#: ``src/`` must be identical to this commit's, the tree pre-registration 3 fixed.
PREREGISTERED_SRC_OF = "a27142e"
HELD_OUT_SOURCES = ("SRC009", "SRC011", "SRC012")
SOURCE_NAMES = {"SRC009": "SkillHarm", "SRC011": "ATR Skill Security Benchmark", "SRC012": "SkillFortifyBench"}
EXPECTED = {"1": 839, "0": 545}
OPERATING_POINTS: dict[str, tuple[str, ...]] = {
    "block": ("BLOCK",),
    "block_or_review": ("BLOCK", "REVIEW"),
    "block_review_or_caution": ("BLOCK", "REVIEW", "CAUTION"),
}
POINT_LABELS = {
    "block": "BLOCK",
    "block_or_review": "BLOCK or REVIEW",
    "block_review_or_caution": "BLOCK, REVIEW or CAUTION",
}
#: Cisco's published (recall, false-positive rate) on the same split, from
#: docs/reference/measured-results.md at c558c42. Fixed in the pre-registration.
CISCO = {
    "Rules only, balanced, MEDIUM+": (0.080, 0.042),
    "Rules only, balanced, HIGH+": (0.077, 0.040),
    "Rules + Gemma 4 26B judge, balanced, MEDIUM+": (0.667, 0.154),
    "Rules + Gemma 4 26B judge, balanced, HIGH+": (0.337, 0.064),
}
VERDICTS = ("BLOCK", "REVIEW", "CAUTION", "CLEAR", "INCONCLUSIVE", "ERROR", "NO_SKILL")
#: Families whose findings can move the verdict (model/result.py DIMENSION_FAMILIES,
#: less the isolated specification and quality dimensions).
VERDICT_DIMENSIONS = ("security", "capability", "supply_chain")
OPENING = 300
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_WHITESPACE = re.compile(r"\s+")


# -- the corpus ---------------------------------------------------------------------


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def ensure_files(cache: Path) -> None:
    for name, (size, digest) in FILES.items():
        path = fetch(resolve_url(DATASET, PIN, name), cache / name)
        if path.stat().st_size != size or _sha256(path) != digest:
            raise SystemExit(f"{name} does not match the pinned size and SHA-256; refusing to measure")


def load_test_rows(cache: Path) -> list[dict]:
    """The source-disjoint test members, joined to the primary table, checked."""
    import pyarrow.parquet as pq  # evaluation-only dependency

    manifest = pq.read_table(cache / "splits/source_disjoint.parquet").to_pylist()
    members = {r["benchmark_id"]: r for r in manifest if r["split"] == "test"}
    columns = ["benchmark_id", "label", "skill_text", "public_skill_text", "text_available", "text_redacted",
               "original_text_withheld", "source_id", "attack_categories"]
    rows = [r for r in pq.read_table(cache / "primary.parquet", columns=columns).to_pylist()
            if r["benchmark_id"] in members]
    if len(rows) != len(members) or len({r["benchmark_id"] for r in rows}) != len(rows):
        raise SystemExit("split manifest and primary table disagree on the test members")
    for row in rows:
        entry = members[row["benchmark_id"]]
        if row["label"] != entry["label"] or row["source_id"] != entry["source_id"]:
            raise SystemExit(f"{row['benchmark_id']}: manifest and primary table disagree")
        if row["source_id"] not in HELD_OUT_SOURCES:
            raise SystemExit(f"{row['benchmark_id']}: test member from a source that is not held out")
        if row["text_available"] != (row["skill_text"] is not None):
            raise SystemExit(f"{row['benchmark_id']}: text_available disagrees with skill_text")
        text = row["skill_text"] if row["skill_text"] is not None else row["public_skill_text"]
        if not isinstance(text, str) or not text:
            raise SystemExit(f"{row['benchmark_id']}: no readable skill text")
        row["text"] = text
    if Counter(r["label"] for r in rows) != Counter(EXPECTED):
        raise SystemExit(f"unexpected label counts {Counter(r['label'] for r in rows)}")
    return sorted(rows, key=lambda r: r["benchmark_id"])


def materialise(rows: list[dict], into: Path) -> None:
    """One directory per identity holding only SKILL.md. Nothing is executed."""
    if into.exists():
        shutil.rmtree(into)
    into.mkdir(mode=0o700, parents=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for row in rows:
        identity = row["benchmark_id"]
        if not _SAFE_ID.fullmatch(identity):
            raise SystemExit(f"unsafe benchmark_id {identity!r}")
        directory = into / identity
        directory.mkdir(mode=0o700)
        with os.fdopen(os.open(directory / "SKILL.md", flags, 0o600), "w", encoding="utf-8", newline="") as fh:
            fh.write(row["text"])
        row["dir"] = str(directory)
    found = sorted(p.relative_to(into).as_posix() for p in into.rglob("*") if p.is_file())
    if found != sorted(f"{r['benchmark_id']}/SKILL.md" for r in rows):
        raise SystemExit("materialised tree holds something other than one SKILL.md per identity")


# -- independence -----------------------------------------------------------------------


def _keys(text: str) -> tuple[str, str]:
    flat = _WHITESPACE.sub("", text)
    return (hashlib.sha256(flat.encode()).hexdigest(), hashlib.sha256(flat[:OPENING].encode()).hexdigest())


def _texts_from_jsonl(paths: Iterable[Path]) -> Iterable[str]:
    for path in paths:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                text = json.loads(line).get("skill_md_content")
                if isinstance(text, str) and text:
                    yield text


def _overlap(rows: list[dict], texts: Iterable[str]) -> dict:
    exact: dict[str, list[str]] = defaultdict(list)
    opening: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        full, head = _keys(row["text"])
        exact[full].append(row["benchmark_id"])
        opening[head].append(row["benchmark_id"])
    seen = 0
    exact_hits: set[str] = set()
    opening_hits: set[str] = set()
    for text in texts:
        seen += 1
        full, head = _keys(text)
        exact_hits.update(exact.get(full, ()))
        opening_hits.update(opening.get(head, ()))
    return {"texts_compared": seen, "exact": sorted(exact_hits), "same_opening": sorted(opening_hits)}


def independence(rows: list[dict], clawhub_dev: list[Path]) -> dict:
    tracked = subprocess.run(["git", "ls-files", "*SKILL.md"], cwd=REPO_ROOT,  # noqa: S607
                             capture_output=True, text=True, check=True).stdout.split()
    report = {
        "method": f"SHA-256 of the text with all whitespace removed, whole and first {OPENING} characters",
        "repository_skill_md": _overlap(rows, ((REPO_ROOT / p).read_text(encoding="utf-8") for p in tracked)),
    }
    if clawhub_dev:
        report["clawhub_development_rows"] = _overlap(rows, _texts_from_jsonl(clawhub_dev))
    else:
        report["clawhub_development_rows"] = "not run (no --clawhub-dev files given)"
    return report


#: The ClawHub development rows the false-positive work before pre-registration 2
#: actually scanned: those whose bundle holds JavaScript, TypeScript or Python, or
#: an extensionless script with a shebang. This re-derives exactly the 4,806 rows
#: that work used, from the dataset alone.
_CODE_SUFFIXES = frozenset({".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"})


def _development_scope(bundle: list[dict] | None) -> bool:
    for item in bundle or ():
        suffix = PurePosixPath(item.get("path") or "").suffix.lower()
        if suffix in _CODE_SUFFIXES or (not suffix and (item.get("content") or "").startswith("#!")):
            return True
    return False


def overlap_detail(cache: Path, clawhub_dev: list[Path]) -> dict:
    """Split the ClawHub overlap by whether the development work scanned the matching row.

    Added after the measurement, to say precisely what the overlap is; it scans
    nothing and changes no recorded figure.
    """
    rows = load_test_rows(cache)
    exact: dict[str, set[str]] = defaultdict(set)
    opening: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        full, head = _keys(row["text"])
        exact[full].add(row["benchmark_id"])
        opening[head].add(row["benchmark_id"])
    scanned: set[str] = set()
    unscanned: set[str] = set()
    in_scope = 0
    for path in clawhub_dev:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                record = json.loads(line)
                is_scoped = _development_scope(record.get("skill_bundle_content"))
                in_scope += is_scoped
                text = record.get("skill_md_content")
                if not isinstance(text, str) or not text:
                    continue
                full, head = _keys(text)
                matched = exact.get(full, set()) | opening.get(head, set())
                (scanned if is_scoped else unscanned).update(matched)
    label = {r["benchmark_id"]: ("malicious" if r["label"] == "1" else "benign", r["source_id"]) for r in rows}

    def describe(ids: set[str]) -> dict:
        counts = Counter(f"{kind} {source}" for kind, source in (label[i] for i in ids))
        return {"identities": len(ids), "by_label_and_source": dict(sorted(counts.items()))}

    return {
        "development_rows_scanned": in_scope,
        "matching_a_row_the_development_work_scanned": describe(scanned),
        "matching_only_rows_it_never_scanned": describe(unscanned - scanned),
        "all_overlapping": len(scanned | unscanned),
    }


# -- scanning, in worker processes ------------------------------------------------------


def _init_worker() -> None:
    from skillsniff.engine import load_rules

    load_rules()


def scan_one(directory: str) -> dict:
    from skillsniff.core.config import Config
    from skillsniff.engine import scan

    started = time.perf_counter()
    try:
        result = scan(Path(directory), Config())
    except Exception as exc:  # recorded, never hidden
        return {"verdict": "ERROR", "error": f"{type(exc).__name__}: {exc}"[:300], "rules": {}, "ms": 0.0}
    elapsed = round((time.perf_counter() - started) * 1000, 1)
    if not result.skills:
        return {"verdict": "NO_SKILL", "rules": {}, "ms": elapsed}
    skill = result.skills[0]
    by_severity: dict[str, set[str]] = defaultdict(set)
    for key in VERDICT_DIMENSIONS:
        dimension = skill.risk.dimensions.get(key)
        for finding in dimension.findings if dimension else ():
            if finding.severity.value in ("critical", "high", "medium"):
                by_severity[finding.severity.value].add(finding.rule_id)
    return {
        "verdict": skill.risk.verdict.value,
        "coverage": skill.coverage.confidence,
        "rules": {k: sorted(v) for k, v in sorted(by_severity.items())},
        "ms": elapsed,
    }


def scan_all(directories: list[str], workers: int) -> list[dict]:
    started = time.monotonic()
    out: list[dict] = []
    with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker) as pool:
        for n, result in enumerate(pool.map(scan_one, directories, chunksize=8), 1):
            out.append(result)
            if n % 250 == 0:
                print(f"  {n}/{len(directories)} in {time.monotonic() - started:.0f}s", file=sys.stderr)
    return out


# -- metrics ----------------------------------------------------------------------------


def point(cases: list[dict], detected: tuple[str, ...]) -> dict:
    malicious = [c for c in cases if c["label"] == "1"]
    benign = [c for c in cases if c["label"] == "0"]
    tp = sum(c["verdict"] in detected for c in malicious)
    fp = sum(c["verdict"] in detected for c in benign)
    fn, tn = len(malicious) - tp, len(benign) - fp
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall": _rate(tp, tp + fn),
        "false_positive_rate": _rate(fp, fp + tn),
        "precision": _rate(tp, tp + fp),
        "f1": round(2 * tp / (2 * tp + fp + fn), 4) if tp else 0.0,
    }


def points(cases: list[dict]) -> dict:
    return {name: point(cases, verdicts) for name, verdicts in OPERATING_POINTS.items()}


def compare(measured: dict) -> list[dict]:
    """Each Cisco figure against the SkillSniff point with the closest false-positive rate."""
    out = []
    for name, (recall, fpr) in CISCO.items():
        key = min(measured, key=lambda k: abs(measured[k]["false_positive_rate"]["rate"] - fpr))
        ours = measured[key]
        low, high = ours["recall"]["wilson95"]
        tp, fp = recall * EXPECTED["1"], fpr * EXPECTED["0"]
        out.append({
            "cisco": name, "cisco_recall": recall, "cisco_false_positive_rate": fpr,
            "cisco_precision_derived": round(tp / (tp + fp), 4),
            "cisco_f1_derived": round(2 * tp / (2 * tp + fp + (EXPECTED["1"] - tp)), 4),
            "skillsniff_point": key, "skillsniff_recall": ours["recall"],
            "skillsniff_false_positive_rate": ours["false_positive_rate"],
            "skillsniff_precision": ours["precision"], "skillsniff_f1": ours["f1"],
            "cisco_recall_against_skillsniff_interval": "above" if recall > high else "below" if recall < low else "inside",
        })
    return out


def by_group(cases: list[dict], groups: dict[str, list[dict]]) -> dict:
    out = {}
    for name, members in groups.items():
        counts = Counter(c["label"] for c in members)
        entry: dict = {"malicious": counts["1"], "benign": counts["0"]}
        for key, verdicts in OPERATING_POINTS.items():
            measured = point(members, verdicts)
            entry[key] = {"recall": measured["recall"] if counts["1"] else None,
                          "false_positive_rate": measured["false_positive_rate"] if counts["0"] else None}
        out[name] = entry
    return out


def rule_counts(cases: list[dict]) -> dict:
    """Identities on which each verdict-bearing rule fired at HIGH or above."""
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for case in cases:
        fired = set(case["rules"].get("critical", ())) | set(case["rules"].get("high", ()))
        for rule in fired:
            counts[rule]["malicious" if case["label"] == "1" else "benign"] += 1
    ordered = sorted(counts.items(), key=lambda kv: (-(kv[1]["malicious"] + kv[1]["benign"]), kv[0]))
    return {rule: {"malicious": c["malicious"], "benign": c["benign"]} for rule, c in ordered}


def summarise(cases: list[dict]) -> dict:
    measured = points(cases)
    by_source: dict[str, list[dict]] = defaultdict(list)
    by_attack: dict[str, list[dict]] = defaultdict(list)
    for case in cases:
        by_source[case["source_id"]].append(case)
        if case["label"] == "1":
            for category in case["attack_categories"] or ["(no attack category mapped)"]:
                by_attack[category].append(case)
    verdicts = {label: Counter(c["verdict"] for c in cases if c["label"] == label) for label in ("1", "0")}
    timings = [c["ms"] for c in cases if c["verdict"] not in ("ERROR",)]
    return {
        "cases": len(cases),
        "operating_points": measured,
        "against_cisco_at_matched_fpr": compare(measured),
        "verdicts": {("malicious" if k == "1" else "benign"): {v: n[v] for v in VERDICTS} for k, n in verdicts.items()},
        "by_source": by_group(cases, {f"{s} {SOURCE_NAMES[s]}": by_source[s] for s in HELD_OUT_SOURCES}),
        "by_attack_category": by_group(cases, dict(sorted(by_attack.items(), key=lambda kv: -len(kv[1])))),
        "rules_at_high_or_above": rule_counts(cases),
        "errors": [{"id": c["benchmark_id"], "error": c.get("error")} for c in cases if c["verdict"] == "ERROR"],
        "median_ms_per_skill": round(statistics.median(timings), 1) if timings else None,
    }


# -- run and render ----------------------------------------------------------------------


def preregistered_tree() -> dict:
    def tree(rev: str) -> str:
        return subprocess.run(["git", "rev-parse", f"{rev}:src"], cwd=REPO_ROOT,  # noqa: S603, S607
                              capture_output=True, text=True, check=True).stdout.strip()

    commit = scanned_commit()
    if tree("HEAD") != tree(PREREGISTERED_SRC_OF):
        raise SystemExit(f"src/ differs from {PREREGISTERED_SRC_OF}, the tree pre-registration 3 fixed")
    return {"scanned_commit": commit, "src_tree": tree("HEAD"), "src_identical_to": PREREGISTERED_SRC_OF}


def run(args: argparse.Namespace) -> int:
    if (args.out / "summary.json").exists():
        raise SystemExit(f"{args.out / 'summary.json'} exists: the split is scanned once")
    provenance = preregistered_tree()
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ensure_files(args.cache)
    rows = load_test_rows(args.cache)
    overlap = independence(rows, args.clawhub_dev)
    materialise(rows, args.cache / "skills")
    wall = time.monotonic()
    results = scan_all([r["dir"] for r in rows], args.workers)
    wall = time.monotonic() - wall
    cases = []
    for row, result in zip(rows, results, strict=True):
        cases.append({"benchmark_id": row["benchmark_id"], "label": row["label"], "source_id": row["source_id"],
                      "attack_categories": row["attack_categories"] or [], **result})

    summary: dict = {
        "protocol": "docs/EXTERNAL_VALIDATION.md, Pre-registration 3",
        "dataset": f"{DATASET}@{PIN}", "split": "source_disjoint, test members",
        **provenance, "started": started,
        "public_skill_text_used": sum(r["skill_text"] is None for r in rows),
        "independence": overlap,
        "all": summarise(cases),
        "scan_wall_seconds": round(wall, 1), "workers": args.workers,
    }
    flagged = set(overlap["repository_skill_md"]["exact"]) | set(overlap["repository_skill_md"]["same_opening"])
    if isinstance(overlap["clawhub_development_rows"], dict):
        flagged |= set(overlap["clawhub_development_rows"]["exact"])
        flagged |= set(overlap["clawhub_development_rows"]["same_opening"])
    if flagged:
        summary["excluding_overlap"] = summarise([c for c in cases if c["benchmark_id"] not in flagged])
    summary["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    args.out.mkdir(parents=True, exist_ok=True)
    keep = ("benchmark_id", "label", "source_id", "verdict", "coverage", "rules")
    with (args.out / "predictions.jsonl").open("w") as fh:
        for case in cases:
            fh.write(json.dumps({k: case.get(k) for k in keep}) + "\n")
    with (args.out / "missed_malicious.jsonl").open("w") as fh:
        for case in cases:
            if case["label"] == "1" and case["verdict"] not in OPERATING_POINTS["block_review_or_caution"]:
                fh.write(json.dumps({k: case.get(k) for k in (*keep, "attack_categories")}) + "\n")
    with (args.out / "false_blocks.jsonl").open("w") as fh:
        for case in cases:
            if case["label"] == "0" and case["verdict"] == "BLOCK":
                fh.write(json.dumps({k: case.get(k) for k in keep}) + "\n")
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(render(summary))
    return 0


def _cell(rate: dict | None) -> str:
    if not rate or not rate["total"]:
        return "—"
    low, high = rate["wilson95"]
    return f"{rate['rate'] * 100:.1f}% ({rate['hits']}/{rate['total']}) [{low * 100:.1f}, {high * 100:.1f}]"


def _short(rate: dict | None) -> str:
    return "—" if not rate or not rate["total"] else f"{rate['rate'] * 100:.1f}%"


def render_block(block: dict) -> list[str]:
    lines = ["| Detected at | Recall | False-positive rate | Precision | F1 |", "| --- | --- | --- | --- | --- |"]
    for key, label in POINT_LABELS.items():
        m = block["operating_points"][key]
        lines.append(f"| {label} | {_cell(m['recall'])} | {_cell(m['false_positive_rate'])} | "
                     f"{_cell(m['precision'])} | {m['f1'] * 100:.1f}% |")
    lines += ["", "Against Cisco's published figures, at the SkillSniff point with the closest false-positive rate:", "",
              "| Cisco configuration | Cisco recall / FPR | SkillSniff point | SkillSniff recall / FPR | Cisco's recall vs SkillSniff's 95% interval |",
              "| --- | --- | --- | --- | --- |"]
    for row in block["against_cisco_at_matched_fpr"]:
        lines.append(f"| {row['cisco']} | {row['cisco_recall'] * 100:.1f}% / {row['cisco_false_positive_rate'] * 100:.1f}% | "
                     f"{POINT_LABELS[row['skillsniff_point']]} | {_short(row['skillsniff_recall'])} / "
                     f"{_short(row['skillsniff_false_positive_rate'])} | {row['cisco_recall_against_skillsniff_interval']} |")
    lines += ["", "Verdicts:", "", "| Label | " + " | ".join(VERDICTS) + " |", "| --- |" + " --- |" * len(VERDICTS)]
    for label, counts in block["verdicts"].items():
        lines.append(f"| {label} | " + " | ".join(str(counts[v]) for v in VERDICTS) + " |")
    lines += ["", "By held-out source:", "", "| Source | Malicious / benign | Recall, BLOCK | FPR, BLOCK | "
              "Recall, BLOCK or REVIEW | FPR, BLOCK or REVIEW |", "| --- | --- | --- | --- | --- | --- |"]
    for name, g in block["by_source"].items():
        lines.append(f"| {name} | {g['malicious']} / {g['benign']} | {_short(g['block']['recall'])} | "
                     f"{_short(g['block']['false_positive_rate'])} | {_short(g['block_or_review']['recall'])} | "
                     f"{_short(g['block_or_review']['false_positive_rate'])} |")
    lines += ["", "Recall by attack category (malicious only; an identity can carry several):", "",
              "| Attack category | Malicious | Recall, BLOCK | Recall, BLOCK or REVIEW | Recall, BLOCK, REVIEW or CAUTION |",
              "| --- | --- | --- | --- | --- |"]
    for name, g in block["by_attack_category"].items():
        lines.append(f"| {name} | {g['malicious']} | {_short(g['block']['recall'])} | "
                     f"{_short(g['block_or_review']['recall'])} | {_short(g['block_review_or_caution']['recall'])} |")
    lines += ["", "Rules firing at HIGH or above (identities):", "", "| Rule | Malicious | Benign |", "| --- | --- | --- |"]
    for rule, c in block["rules_at_high_or_above"].items():
        lines.append(f"| `{rule}` | {c['malicious']} | {c['benign']} |")
    return lines


def render(summary: dict) -> str:
    lines = [f"Scanned commit `{summary['scanned_commit']}` (`src/` identical to `{summary['src_identical_to']}`), "
             f"{summary['started']} to {summary['finished']}; {summary['all']['cases']} identities, "
             f"{summary['public_skill_text_used']} from `public_skill_text`; scan wall time "
             f"{summary['scan_wall_seconds']} s on {summary['workers']} workers, median "
             f"{summary['all']['median_ms_per_skill']} ms per skill.", ""]
    ind = summary["independence"]
    repo = ind["repository_skill_md"]
    lines.append(f"Overlap audit ({ind['method']}): repository SKILL.md files {len(repo['exact'])} exact / "
                 f"{len(repo['same_opening'])} same-opening of {repo['texts_compared']} compared.")
    claw = ind["clawhub_development_rows"]
    if isinstance(claw, dict):
        lines.append(f"ClawHub development rows: {len(claw['exact'])} exact / {len(claw['same_opening'])} "
                     f"same-opening, {claw['texts_compared']} rows compared.")
    else:
        lines.append(f"ClawHub development rows: {claw}.")
    lines += ["", *render_block(summary["all"])]
    if "excluding_overlap" in summary:
        lines += ["", "#### Excluding identities that overlap development data", "",
                  *render_block(summary["excluding_overlap"])]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=Path, help="download and materialisation directory")
    parser.add_argument("--out", type=Path, help="directory for the results")
    parser.add_argument("--clawhub-dev", type=Path, nargs="*", default=[],
                        help="ClawHub development JSONL files, for the overlap audit")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 2)
    parser.add_argument("--render", type=Path, help="print the Markdown tables for an existing summary.json")
    parser.add_argument("--overlap-detail", action="store_true",
                        help="split the ClawHub overlap by development scope; scans nothing")
    args = parser.parse_args()
    if args.render:
        print(render(json.loads(args.render.read_text())))
        return 0
    if args.overlap_detail:
        if not args.cache or not args.out or not args.clawhub_dev:
            parser.error("--overlap-detail needs --cache, --out and --clawhub-dev")
        ensure_files(args.cache)
        detail = overlap_detail(args.cache, args.clawhub_dev)
        (args.out / "overlap_detail.json").write_text(json.dumps(detail, indent=2) + "\n")
        print(json.dumps(detail, indent=2))
        return 0
    if not args.cache or not args.out:
        parser.error("--cache and --out are required to measure")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
