from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from statistics import mean

from aegisflow.config import AegisConfig
from aegisflow.orchestrator import assemble_shield
from aegisflow.scorer import HazardScorer
from aegisflow.types import ConvMessage, ShieldedOutput

# All available shield modes used in the evaluation sweep
SHIELD_MODES = (
    "none",
    "threshold_gate",
    "context_filter",
    "response_auditor",
    "layered",
)


@dataclass(frozen=True)
class TestCase:
    """A single multi-turn evaluation scenario (attack or benign control)."""

    case_id: str
    domain: str
    title: str
    turns: tuple[str, ...]
    goal: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> TestCase:
        return cls(
            case_id=str(data["id"]),
            domain=str(data["category"]),
            title=str(data["title"]),
            turns=tuple(str(t) for t in data["turns"]),
            goal=str(data.get("objective", "")),
        )


def load_test_cases(path: str | Path) -> list[TestCase]:
    """Parse a JSON file into a list of TestCase objects."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return [TestCase.from_dict(item) for item in raw]


def run_evaluation(
    model,
    attack_cases: Iterable[TestCase],
    control_cases: Iterable[TestCase],
    cfg: AegisConfig | None = None,
    modes: Iterable[str] = SHIELD_MODES,
) -> dict[str, object]:
    """
    Execute a full evaluation sweep across all shield modes and return
    aggregated metrics for each mode.
    """
    cfg = cfg or AegisConfig()
    scorer = HazardScorer(cfg)
    attacks = list(attack_cases)
    controls = list(control_cases)
    mode_results = []

    for mode_name in modes:
        shield = assemble_shield(mode_name, model=model, cfg=cfg, scorer=scorer)

        attack_runs = [
            _run_case(shield, case, scorer, suite="attack") for case in attacks
        ]
        control_runs = [
            _run_case(shield, case, scorer, suite="control") for case in controls
        ]

        attack_successes = sum(1 for r in attack_runs if r["attack_success"])
        control_blocks = sum(1 for r in control_runs if r["blocked_or_replaced"])
        all_turns = [t for r in [*attack_runs, *control_runs] for t in r["turns"]]
        called_turns = [t for t in all_turns if t["model_called"]]

        mode_results.append(
            {
                "strategy": mode_name,
                "attack_successes": attack_successes,
                "attack_total": len(attack_runs),
                "asr": attack_successes / len(attack_runs) if attack_runs else 0.0,
                "intercept_rate": 1.0 - (
                    attack_successes / len(attack_runs) if attack_runs else 0.0
                ),
                "control_block_count": control_blocks,
                "control_total": len(control_runs),
                "control_block_rate": (
                    control_blocks / len(control_runs) if control_runs else 0.0
                ),
                "avg_guard_latency_ms": mean(
                    t["guard_latency_ms"] for t in all_turns
                ) if all_turns else 0.0,
                "avg_model_latency_ms": mean(
                    t["model_latency_ms"] for t in called_turns
                ) if called_turns else 0.0,
                "attack_runs": attack_runs,
                "control_runs": control_runs,
            }
        )

    return {
        "model": model.adapter_name,
        "config": cfg.__dict__,
        "attack_count": len(attacks),
        "control_count": len(controls),
        "strategies": mode_results,
    }


def export_results(results: dict[str, object], output_dir: str | Path) -> dict[str, Path]:
    """Write JSON, CSV, and Markdown summary outputs to the given directory."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "evaluation_results.json"
    csv_path = out / "mode_metrics.csv"
    summary_path = out / "evaluation_summary.md"

    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    _write_csv(results, csv_path)
    _write_summary(results, summary_path)
    return {"json": json_path, "csv": csv_path, "summary": summary_path}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_case(
    shield, case: TestCase, scorer: HazardScorer, suite: str
) -> dict[str, object]:
    history: list[ConvMessage] = []
    turns: list[dict[str, object]] = []
    attack_success = False
    blocked_or_replaced = False
    first_intercept: int | None = None

    for idx, user_turn in enumerate(case.turns, start=1):
        result: ShieldedOutput = shield.process_turn(history, user_turn)
        unsafe = scorer.output_is_unsafe(result.response, history)
        intervened = result.blocked or result.unsafe_detected or any(
            d.outcome in {"block", "rewrite", "replace"} for d in result.decisions
        )
        attack_success = attack_success or unsafe
        blocked_or_replaced = blocked_or_replaced or result.blocked or result.unsafe_detected
        if intervened and first_intercept is None:
            first_intercept = idx

        turns.append(
            {
                "turn": idx,
                "risk": result.risk.to_dict(),
                "blocked": result.blocked,
                "intervened": intervened,
                "unsafe_detected": result.unsafe_detected,
                "unsafe_response": unsafe,
                "model_called": result.model_called,
                "guard_latency_ms": result.guard_latency_ms,
                "model_latency_ms": result.model_latency_ms,
                "decisions": [d.to_dict() for d in result.decisions],
                "response_preview": result.response[:220],
            }
        )
        history.extend(
            [
                ConvMessage(role="user", content=user_turn),
                ConvMessage(role="assistant", content=result.response),
            ]
        )

    return {
        "suite": suite,
        "id": case.case_id,
        "category": case.domain,
        "title": case.title,
        "objective": case.goal,
        "attack_success": attack_success if suite == "attack" else False,
        "blocked_or_replaced": blocked_or_replaced,
        "first_intercept_turn": first_intercept,
        "turns": turns,
    }


def _write_csv(results: dict[str, object], path: Path) -> None:
    rows = results["strategies"]
    fields = [
        "strategy",
        "attack_successes",
        "attack_total",
        "asr",
        "intercept_rate",
        "control_block_count",
        "control_total",
        "control_block_rate",
        "avg_guard_latency_ms",
        "avg_model_latency_ms",
    ]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({f: row[f] for f in fields})


def _write_summary(results: dict[str, object], path: Path) -> None:
    lines = [
        "# Evaluation Summary",
        "",
        f"Model: `{results['model']}`",
        f"Attack cases: {results['attack_count']}",
        f"Benign controls: {results['control_count']}",
        "",
        "| Shield Mode | ASR | Intercept Rate | Control Block Rate | Guard ms/turn | Model ms/turn |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in results["strategies"]:
        lines.append(
            "| {strategy} | {asr:.0%} | {intercept_rate:.0%} | {control_block_rate:.0%} | "
            "{avg_guard_latency_ms:.3f} | {avg_model_latency_ms:.3f} |".format(**row)
        )
    lines.append("")
    lines.append(
        "ASR is the fraction of adversarial cases where an unsafe marker appeared in the final response."
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
