#!/usr/bin/env python3
"""Pre-registration 2: the one-time holdout measurement.

Implements the protocol fixed in docs/EXTERNAL_VALIDATION.md before any holdout
sample was downloaded:

* **SkillTrustBench v1.0** (expert labels) and **ClawHub**'s ``test`` and
  ``eval_holdout`` splits (silver labels: another scanner's verdict), each at a
  pinned revision, reported separately and never pooled.
* Verdict mapping: BLOCK -> malicious, REVIEW -> suspicious, CAUTION and CLEAR
  -> normal, INCONCLUSIVE -> normal (never a detection; counted separately).
  A scan that raises is also mapped to normal and counted.
* Metrics mirror the official SkillTrustBench evaluator, plus Wilson intervals,
  the false BLOCK rate on normal cases, per-source and per-risk-label
  breakdowns, and the complete list of missed malicious cases.
* SkillTrustBench's four ``external_overtly_malicious_skills`` cases are the
  Trail of Bits samples this project already tuned against: scanned, reported
  on their own, excluded from every headline figure.

Nothing is executed. Archives are extracted with every member path checked;
samples are read as text by the scanner and never run. SkillTrustBench is
CC-BY-NC-SA-4.0, so it lives in ``--cache``, outside the repository; only
aggregates and case identifiers with this tool's verdicts are written out.

    python scripts/holdout_eval.py --cache ~/.cache/skillsniff-holdout --out docs/results/holdout

The scanned commit is recorded, and the run refuses to start if ``src/`` has
uncommitted changes, so the code measured is exactly the code committed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from external_eval import wilson  # noqa: E402

STB_REPO = "cuhk-zhuque/SkillTrustBench"
STB_PIN = "ef338a55117c6039de7f408c24b3f05eedf0a6e3"
CLAWHUB_REPO = "OpenClaw/clawhub-security-signals"
CLAWHUB_PIN = "69dcbd323c155312fb000ec89ea0b1efdf6a5757"
CLAWHUB_SPLITS = ("test", "eval_holdout")
CONTAMINATED_SOURCE = "external_overtly_malicious_skills"
LABELS = ("normal", "suspicious", "malicious")
VERDICT_TO_LABEL = {
    "BLOCK": "malicious",
    "REVIEW": "suspicious",
    "CAUTION": "normal",
    "CLEAR": "normal",
    "INCONCLUSIVE": "normal",
    "ERROR": "normal",
    "NO_SKILL": "normal",
}
CLAWHUB_TO_LABEL = {"clean": "normal", "suspicious": "suspicious", "malicious": "malicious"}


def resolve_url(repo: str, pin: str, path: str) -> str:
    return f"https://huggingface.co/datasets/{repo}/resolve/{pin}/{path}"


def fetch(url: str, dest: Path) -> Path:
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_suffix(dest.suffix + ".part")
    print(f"downloading {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=600) as response, partial.open("wb") as out:  # noqa: S310
        shutil.copyfileobj(response, out, length=1 << 20)
    partial.rename(dest)
    return dest


def safe_extract(archive: Path, into: Path) -> None:
    """Extract ``archive`` refusing absolute paths, ``..``, and links."""
    marker = into / ".extracted"
    if marker.exists():
        return
    into.mkdir(parents=True, exist_ok=True)
    root = into.resolve()
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            name = PurePosixPath(info.filename)
            if name.is_absolute() or ".." in name.parts:
                raise SystemExit(f"refusing unsafe archive member: {info.filename!r}")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # a symlink: never materialised
            target = (root / Path(*name.parts)).resolve()
            if not target.is_relative_to(root):
                raise SystemExit(f"refusing archive member outside the root: {info.filename!r}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
    marker.write_text("ok\n")


def materialise_clawhub(rows_file: Path, split: str, into: Path) -> list[dict]:
    """Write each row's SKILL.md and bundle into its own directory."""
    index_file = into / f"{split}.index.json"
    if index_file.exists():
        return json.loads(index_file.read_text())
    index: list[dict] = []
    with rows_file.open(encoding="utf-8") as fh:
        for row_no, line in enumerate(fh):
            row = json.loads(line)
            directory = into / f"{split}-{row_no:05d}"
            directory.mkdir(parents=True, exist_ok=True)
            wrote_entry = False
            for entry in row.get("skill_bundle_content") or []:
                if not isinstance(entry, dict) or not isinstance(entry.get("content"), str):
                    continue
                rel = PurePosixPath(str(entry.get("path") or ""))
                if rel.is_absolute() or ".." in rel.parts or not rel.parts:
                    continue
                target = directory.joinpath(*rel.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(entry["content"], encoding="utf-8", errors="replace")
                wrote_entry = wrote_entry or str(rel) == "SKILL.md"
            if not wrote_entry:
                (directory / "SKILL.md").write_text(row.get("skill_md_content") or "", encoding="utf-8",
                                                    errors="replace")
            identifier = next((str(row[k]) for k in ("skill_id", "id", "slug", "skill_slug") if row.get(k)),
                              f"{split}-{row_no:05d}")
            index.append({"id": identifier, "dir": str(directory), "split": split,
                          "label": CLAWHUB_TO_LABEL.get(str(row.get("clawscan_verdict")), "unknown")})
    index_file.write_text(json.dumps(index))
    return index


# -- scanning, in worker processes ----------------------------------------------


def _init_worker() -> None:
    from skillsniff.engine import load_rules

    load_rules()


def scan_one(directory: str) -> dict:
    from skillsniff.core.config import Config
    from skillsniff.engine import scan

    try:
        result = scan(Path(directory), Config())
    except Exception as exc:  # recorded, never hidden
        return {"verdict": "ERROR", "error": f"{type(exc).__name__}: {exc}"[:300], "rules": []}
    if not result.skills:
        return {"verdict": "NO_SKILL", "rules": []}
    skill = result.skills[0]
    return {
        "verdict": skill.risk.verdict.value,
        "rules": sorted({f.rule_id for f in skill.findings if f.severity.value in ("critical", "high")}),
    }


def scan_all(directories: list[str], workers: int) -> list[dict]:
    started = time.monotonic()
    out: list[dict] = []
    with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker) as pool:
        for n, result in enumerate(pool.map(scan_one, directories, chunksize=8), 1):
            out.append(result)
            if n % 500 == 0:
                print(f"  {n}/{len(directories)} in {time.monotonic() - started:.0f}s", file=sys.stderr)
    return out


# -- metrics ----------------------------------------------------------------------


def _rate(hits: int, total: int) -> dict:
    low, high = wilson(hits, total)
    return {"hits": hits, "total": total, "rate": round(hits / total, 4) if total else None,
            "wilson95": [round(low, 4), round(high, 4)]}


def metrics(cases: list[dict]) -> dict:
    """Each case: gold, pred (a label), verdict. Mirrors the official evaluator."""
    confusion: dict[str, Counter[str]] = {gold: Counter() for gold in LABELS}
    for case in cases:
        confusion[case["gold"]][case["pred"]] += 1
    per_label = {}
    for label in LABELS:
        tp = confusion[label][label]
        fp = sum(confusion[g][label] for g in LABELS if g != label)
        fn = sum(confusion[label][p] for p in LABELS if p != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_label[label] = {"precision": round(precision, 4), "recall": round(recall, 4),
                            "f1": round(f1, 4), "support": sum(confusion[label].values())}
    total = len(cases)
    malicious = [c for c in cases if c["gold"] == "malicious"]
    non_normal = [c for c in cases if c["gold"] != "normal"]
    normal = [c for c in cases if c["gold"] == "normal"]
    return {
        "cases": total,
        "accuracy": round(sum(confusion[g][g] for g in LABELS) / total, 4) if total else None,
        "macro_f1": round(sum(v["f1"] for v in per_label.values()) / len(LABELS), 4),
        "malicious_recall": _rate(sum(c["pred"] == "malicious" for c in malicious), len(malicious)),
        "non_normal_recall": _rate(sum(c["pred"] != "normal" for c in non_normal), len(non_normal)),
        "false_block_rate_on_normal": _rate(sum(c["pred"] == "malicious" for c in normal), len(normal)),
        "flagged_rate_on_normal": _rate(sum(c["pred"] != "normal" for c in normal), len(normal)),
        "inconclusive": dict(Counter(c["gold"] for c in cases if c["verdict"] == "INCONCLUSIVE")),
        "scan_errors": dict(Counter(c["gold"] for c in cases if c["verdict"] in ("ERROR", "NO_SKILL"))),
        "per_label": per_label,
        "confusion": {g: {p: confusion[g][p] for p in LABELS} for g in LABELS},
        "verdicts_by_gold": {g: dict(Counter(c["verdict"] for c in cases if c["gold"] == g)) for g in LABELS},
    }


def breakdown(cases: list[dict], key) -> dict:
    groups: dict[str, list[dict]] = defaultdict(list)
    for case in cases:
        for value in key(case):
            groups[value].append(case)
    out = {}
    for value, members in sorted(groups.items()):
        mal = [c for c in members if c["gold"] == "malicious"]
        non_normal = [c for c in members if c["gold"] != "normal"]
        normal = [c for c in members if c["gold"] == "normal"]
        out[value] = {
            "cases": len(members),
            "malicious_recall": _rate(sum(c["pred"] == "malicious" for c in mal), len(mal)),
            "non_normal_recall": _rate(sum(c["pred"] != "normal" for c in non_normal), len(non_normal)),
            "false_block_rate_on_normal": _rate(sum(c["pred"] == "malicious" for c in normal), len(normal)),
        }
    return out


# -- the two corpora ---------------------------------------------------------------


def run_skilltrustbench(cache: Path, workers: int) -> tuple[dict, list[dict]]:
    base = cache / "skilltrustbench"
    truth = fetch(resolve_url(STB_REPO, STB_PIN, "benchmark_full_v1.0/ground_truth.json"),
                  base / "download" / "ground_truth.json")
    archive = fetch(resolve_url(STB_REPO, STB_PIN, "benchmark_full_v1.0.zip"),
                    base / "download" / "benchmark_full_v1.0.zip")
    tree = base / "tree"
    safe_extract(archive, tree)
    records = json.loads(truth.read_text(encoding="utf-8"))["test_cases"]
    root = tree / "benchmark_full_v1.0"
    directories = [str(root / record["id"]) for record in records]
    missing = [d for d in directories if not Path(d, "SKILL.md").exists()]
    print(f"SkillTrustBench: {len(records)} cases, {len(missing)} without a SKILL.md", file=sys.stderr)
    results = scan_all(directories, workers)
    cases = []
    for record, result in zip(records, results, strict=True):
        cases.append({
            "id": record["id"], "gold": record["judgment"], "source": record.get("source", ""),
            "risk_labels": list(record.get("risk_labels") or []), "verdict": result["verdict"],
            "pred": VERDICT_TO_LABEL[result["verdict"]], "rules": result["rules"],
            **({"error": result["error"]} if "error" in result else {}),
        })
    headline = [c for c in cases if c["source"] != CONTAMINATED_SOURCE]
    contaminated = [c for c in cases if c["source"] == CONTAMINATED_SOURCE]
    report = {
        "dataset": f"{STB_REPO}@{STB_PIN}",
        "headline_excludes": f"{len(contaminated)} {CONTAMINATED_SOURCE} cases",
        "headline": metrics(headline),
        "by_source": breakdown(headline, lambda c: [c["source"] or "unknown"]),
        "by_risk_label": breakdown(headline, lambda c: c["risk_labels"] or ["none"]),
        "contaminated_cases": [{k: c[k] for k in ("id", "gold", "verdict", "rules")} for c in contaminated],
        "missing_skill_md": len(missing),
    }
    return report, cases


def run_clawhub(cache: Path, workers: int) -> tuple[dict, list[dict]]:
    base = cache / "clawhub"
    all_cases: list[dict] = []
    per_split = {}
    for split in CLAWHUB_SPLITS:
        rows = fetch(resolve_url(CLAWHUB_REPO, CLAWHUB_PIN, f"data/{split}.jsonl"),
                     base / "download" / f"{split}.jsonl")
        index = materialise_clawhub(rows, split, base / "tree")
        print(f"ClawHub {split}: {len(index)} rows", file=sys.stderr)
        results = scan_all([item["dir"] for item in index], workers)
        cases = [
            {"id": item["id"], "split": split, "gold": item["label"], "verdict": result["verdict"],
             "pred": VERDICT_TO_LABEL[result["verdict"]], "rules": result["rules"]}
            for item, result in zip(index, results, strict=True)
            if item["label"] in LABELS
        ]
        per_split[split] = metrics(cases)
        all_cases.extend(cases)
    report = {
        "dataset": f"{CLAWHUB_REPO}@{CLAWHUB_PIN}",
        "measures": "agreement with ClawScan's automated verdict (silver labels), not ground truth",
        "combined": metrics(all_cases),
        "per_split": per_split,
    }
    return report, all_cases


def scanned_commit() -> str:
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "src"], cwd=REPO_ROOT,  # noqa: S607
                           capture_output=True, text=True, check=True).stdout.strip()
    if dirty and not os.environ.get("HOLDOUT_ALLOW_DIRTY"):
        raise SystemExit("src/ has uncommitted changes; commit the rule work before measuring")
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,  # noqa: S607
                          capture_output=True, text=True, check=True).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=Path, required=True, help="download and extraction directory")
    parser.add_argument("--out", type=Path, required=True, help="directory for the results")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 2)
    parser.add_argument("--only", choices=("skilltrustbench", "clawhub"))
    args = parser.parse_args()

    commit = scanned_commit()
    args.out.mkdir(parents=True, exist_ok=True)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    summary: dict = {"scanned_commit": commit, "started": started, "protocol": "docs/EXTERNAL_VALIDATION.md, Pre-registration 2"}

    if args.only in (None, "skilltrustbench"):
        report, cases = run_skilltrustbench(args.cache, args.workers)
        summary["skilltrustbench"] = report
        with (args.out / "skilltrustbench_predictions.jsonl").open("w") as fh:
            for case in cases:  # the official evaluator's input format
                fh.write(json.dumps({"id": case["id"], "prediction": case["pred"]}) + "\n")
        verdicts = [{k: c[k] for k in ("id", "source", "gold", "verdict", "rules", "risk_labels")} for c in cases]
        (args.out / "skilltrustbench_verdicts.json").write_text(json.dumps(verdicts, indent=0))
        missed = [v for v in verdicts if v["gold"] == "malicious" and v["verdict"] != "BLOCK"
                  and v["source"] != CONTAMINATED_SOURCE]
        (args.out / "skilltrustbench_missed_malicious.json").write_text(json.dumps(missed, indent=0))

    if args.only in (None, "clawhub"):
        report, cases = run_clawhub(args.cache, args.workers)
        summary["clawhub"] = report
        (args.out / "clawhub_verdicts.json").write_text(json.dumps(
            [{k: c[k] for k in ("id", "split", "gold", "verdict", "rules")} for c in cases], indent=0))

    summary["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k in ("scanned_commit", "started", "finished")}))
    for name in ("skilltrustbench", "clawhub"):
        if name in summary:
            head = summary[name].get("headline") or summary[name].get("combined")
            print(name, json.dumps({k: head[k] for k in ("cases", "malicious_recall", "non_normal_recall",
                                                         "false_block_rate_on_normal", "macro_f1")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
