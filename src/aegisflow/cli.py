from __future__ import annotations

import argparse
from pathlib import Path

from aegisflow.config import AegisConfig
from aegisflow.clients import SimulatedLlama, HFLlamaBridge
from aegisflow.evaluator import SHIELD_MODES, load_test_cases, run_evaluation, export_results
from aegisflow.reporting import generate_report

ROOT = Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis-flow")
    subparsers = parser.add_subparsers(dest="command", required=True)

    eval_parser = subparsers.add_parser(
        "run-evaluation", help="Run the AegisFlow sequential-escalation defense evaluation."
    )
    eval_parser.add_argument(
        "--attack-file",
        default=str(ROOT / "data" / "attack_sequences.json"),
    )
    eval_parser.add_argument(
        "--control-file",
        default=str(ROOT / "data" / "safe_controls.json"),
    )
    eval_parser.add_argument(
        "--config-file",
        default=str(ROOT / "configs" / "aegis_config.json"),
    )
    eval_parser.add_argument(
        "--results-dir",
        default=str(ROOT / "results"),
    )
    eval_parser.add_argument(
        "--reports-dir",
        default=str(ROOT / "reports"),
    )
    eval_parser.add_argument(
        "--model",
        choices=["simulated", "hf"],
        default="simulated",
    )
    eval_parser.add_argument(
        "--mode",
        choices=[*SHIELD_MODES, "all"],
        default="all",
    )
    eval_parser.add_argument("--max-new-tokens", type=int, default=160)

    args = parser.parse_args(argv)
    if args.command == "run-evaluation":
        return _run_evaluation(args)
    raise ValueError(f"Unknown command: {args.command!r}")


def _run_evaluation(args) -> int:
    cfg = AegisConfig.from_json(args.config_file)
    attacks = load_test_cases(args.attack_file)
    controls = load_test_cases(args.control_file)

    if args.model == "hf":
        model = HFLlamaBridge(max_new_tokens=args.max_new_tokens)
    else:
        model = SimulatedLlama()

    modes = SHIELD_MODES if args.mode == "all" else (args.mode,)
    results = run_evaluation(model, attacks, controls, cfg=cfg, modes=modes)
    output_paths = export_results(results, args.results_dir)
    report_path = generate_report(results, args.reports_dir)

    print("AegisFlow evaluation complete.")
    for row in results["strategies"]:
        print(
            f"  [{row['strategy']}]  ASR={row['asr']:.0%}  "
            f"intercept={row['intercept_rate']:.0%}  "
            f"control_block={row['control_block_rate']:.0%}  "
            f"guard_ms={row['avg_guard_latency_ms']:.3f}"
        )
    print(f"JSON   : {output_paths['json']}")
    print(f"CSV    : {output_paths['csv']}")
    print(f"Summary: {output_paths['summary']}")
    print(f"Report : {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
