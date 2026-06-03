from __future__ import annotations

from dataclasses import dataclass

from aegisflow.config import AegisConfig
from aegisflow.scorer import HazardScorer
from aegisflow.types import ConvMessage, GuardDecision, ThreatReport

# Standard refusal text issued when a request is blocked or replaced
REFUSAL_TEXT = (
    "I am not able to assist with operational harmful instructions or attempts to circumvent "
    "safety guidelines. I can instead offer: prevention strategies, detection methods, "
    "ethical analysis, support resources, or a conceptual treatment that avoids actionable specifics."
)


class BaseFilter:
    """Abstract base class for AegisFlow pipeline filters."""

    stage = "base"

    def pre_generate(
        self, messages: tuple[ConvMessage, ...], report: ThreatReport
    ) -> GuardDecision:
        return GuardDecision(self.stage, "allow", "No pre-generation intervention required.")

    def post_generate(
        self,
        messages: tuple[ConvMessage, ...],
        response: str,
        report: ThreatReport,
    ) -> GuardDecision:
        return GuardDecision(self.stage, "allow", "No post-generation intervention required.")


@dataclass
class ThresholdGate(BaseFilter):
    """
    First-stage filter: blocks the conversation when accumulated risk exceeds
    the halt threshold, preventing the model from being invoked entirely.
    """

    cfg: AegisConfig
    stage = "threshold_gate"

    def pre_generate(
        self, messages: tuple[ConvMessage, ...], report: ThreatReport
    ) -> GuardDecision:
        if report.verdict == "block":
            return GuardDecision(
                stage=self.stage,
                outcome="block",
                rationale=(
                    f"Accumulated risk {report.accumulated_risk:.2f} exceeded "
                    f"halt threshold {self.cfg.halt_threshold:.2f}."
                ),
                override_response=REFUSAL_TEXT,
            )
        return GuardDecision(
            stage=self.stage,
            outcome="allow",
            rationale=f"Accumulated risk {report.accumulated_risk:.2f} is within safe range.",
        )


@dataclass
class ContextFilter(BaseFilter):
    """
    Second-stage filter: replaces a risky conversation history with a compact
    safety envelope when accumulated risk reaches the flag threshold.
    """

    cfg: AegisConfig
    stage = "context_filter"

    def pre_generate(
        self, messages: tuple[ConvMessage, ...], report: ThreatReport
    ) -> GuardDecision:
        if report.accumulated_risk < self.cfg.flag_threshold:
            return GuardDecision(
                stage=self.stage,
                outcome="allow",
                rationale=f"Risk {report.accumulated_risk:.2f} below context filter threshold.",
            )

        domains = ", ".join(report.threats) or "unspecified"
        envelope_system = ConvMessage(
            role="system",
            content=(
                "AegisFlow Safety Envelope: The prior conversation contains potential "
                f"multi-turn escalation in these threat domains: {domains}. "
                "Respond only with refusals, safety education, prevention guidance, or support resources. "
                "Do not supply operational instructions, precise quantities, evasion methods, "
                "capture logic, or any steps that enable harm."
            ),
        )
        envelope_user = ConvMessage(
            role="user",
            content=(
                "The most recent user message has been isolated because it may solicit harmful "
                "operational details. Please provide a brief, safe educational alternative."
            ),
        )
        return GuardDecision(
            stage=self.stage,
            outcome="rewrite",
            rationale="Conversation history replaced with a safety envelope targeting benign output.",
            rewritten_messages=(envelope_system, envelope_user),
        )


@dataclass
class ResponseAuditor(BaseFilter):
    """
    Third-stage filter: scans model output for unsafe markers and replaces
    the response with a refusal if any are detected.
    """

    cfg: AegisConfig
    scorer: HazardScorer
    stage = "response_auditor"

    def post_generate(
        self,
        messages: tuple[ConvMessage, ...],
        response: str,
        report: ThreatReport,
    ) -> GuardDecision:
        if self.scorer.output_is_unsafe(response, messages):
            return GuardDecision(
                stage=self.stage,
                outcome="replace",
                rationale="Model output matched unsafe-output indicators; response replaced.",
                override_response=REFUSAL_TEXT,
            )
        return GuardDecision(
            stage=self.stage,
            outcome="allow",
            rationale="Model output cleared post-generation audit.",
        )
