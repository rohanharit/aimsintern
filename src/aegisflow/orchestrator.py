from __future__ import annotations

import time
from dataclasses import dataclass

from aegisflow.config import AegisConfig
from aegisflow.filters import (
    BaseFilter,
    ContextFilter,
    ResponseAuditor,
    ThresholdGate,
)
from aegisflow.scorer import HazardScorer
from aegisflow.types import ConvMessage, GuardDecision, ShieldedOutput


@dataclass(frozen=True)
class ShieldStrategy:
    """Descriptor pairing a strategy name with its ordered filter stack."""

    name: str
    filters: tuple[BaseFilter, ...]


class ShieldOrchestrator:
    """
    Core pipeline that sequences detection, pre-generation filtering,
    model invocation, and post-generation auditing for every conversation turn.
    """

    def __init__(
        self,
        model,
        filters: tuple[BaseFilter, ...] = (),
        scorer: HazardScorer | None = None,
    ) -> None:
        self.model = model
        self.scorer = scorer or HazardScorer()
        self.filters = filters

    def process_turn(
        self, history: list[ConvMessage], user_text: str
    ) -> ShieldedOutput:
        """Run a single conversation turn through the full shield pipeline."""
        guard_start = time.perf_counter()
        messages: tuple[ConvMessage, ...] = (
            *history,
            ConvMessage(role="user", content=user_text),
        )
        report = self.scorer.evaluate(history, user_text)
        decisions: list[GuardDecision] = []
        model_messages = messages

        # Pre-generation filter pass
        for flt in self.filters:
            decision = flt.pre_generate(model_messages, report)
            decisions.append(decision)
            if decision.outcome == "block":
                return ShieldedOutput(
                    response=decision.override_response or "",
                    blocked=True,
                    unsafe_detected=False,
                    risk=report,
                    decisions=tuple(decisions),
                    guard_latency_ms=(time.perf_counter() - guard_start) * 1000,
                    model_latency_ms=0.0,
                    model_called=False,
                )
            if decision.outcome == "rewrite" and decision.rewritten_messages:
                model_messages = decision.rewritten_messages

        guard_pre_ms = (time.perf_counter() - guard_start) * 1000
        model_start = time.perf_counter()
        response = self.model.generate(list(model_messages))
        model_latency_ms = (time.perf_counter() - model_start) * 1000

        # Post-generation filter pass
        unsafe_detected = False
        for flt in self.filters:
            decision = flt.post_generate(messages, response, report)
            decisions.append(decision)
            if decision.outcome == "replace":
                unsafe_detected = True
                response = decision.override_response or response

        guard_latency_ms = guard_pre_ms + (
            (time.perf_counter() - model_start) * 1000 - model_latency_ms
        )
        return ShieldedOutput(
            response=response,
            blocked=False,
            unsafe_detected=unsafe_detected,
            risk=report,
            decisions=tuple(decisions),
            guard_latency_ms=guard_latency_ms,
            model_latency_ms=model_latency_ms,
            model_called=True,
        )


def assemble_shield(
    mode: str,
    model,
    cfg: AegisConfig | None = None,
    scorer: HazardScorer | None = None,
) -> ShieldOrchestrator:
    """
    Factory function that constructs a ShieldOrchestrator for the given
    shield mode name.

    Supported modes: ``none``, ``threshold_gate``, ``context_filter``,
    ``response_auditor``, ``layered``.
    """
    cfg = cfg or AegisConfig()
    scorer = scorer or HazardScorer(cfg)
    filters: tuple[BaseFilter, ...]

    if mode == "none":
        filters = ()
    elif mode == "threshold_gate":
        filters = (ThresholdGate(cfg),)
    elif mode == "context_filter":
        filters = (ContextFilter(cfg),)
    elif mode == "response_auditor":
        filters = (ResponseAuditor(cfg, scorer),)
    elif mode == "layered":
        filters = (
            ThresholdGate(cfg),
            ContextFilter(cfg),
            ResponseAuditor(cfg, scorer),
        )
    else:
        raise ValueError(f"Unknown shield mode: {mode!r}")

    return ShieldOrchestrator(model=model, filters=filters, scorer=scorer)
