from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

# Role options for a conversation participant
ParticipantRole = Literal["system", "user", "assistant"]


@dataclass(frozen=True)
class ConvMessage:
    """A single message in a multi-turn conversation."""

    role: ParticipantRole
    content: str

    def as_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}

    # backward-compat alias used internally
    def to_dict(self) -> dict[str, str]:
        return self.as_dict()


@dataclass(frozen=True)
class HazardIndicator:
    """A detected signal contributing to the overall hazard score."""

    label: str
    weight: float
    description: str
    evidence: tuple[str, ...] = ()
    domain: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ThreatReport:
    """Aggregated risk evaluation for a single conversation turn."""

    turn_hazard: float
    accumulated_risk: float
    verdict: Literal["allow", "rewrite", "block"]
    threats: dict[str, float] = field(default_factory=dict)
    indicators: tuple[HazardIndicator, ...] = ()
    summary: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "turn_risk": round(self.turn_hazard, 4),
            "cumulative_risk": round(self.accumulated_risk, 4),
            "action": self.verdict,
            "categories": {k: round(v, 4) for k, v in self.threats.items()},
            "signals": [ind.to_dict() for ind in self.indicators],
            "summary": self.summary,
        }


@dataclass(frozen=True)
class GuardDecision:
    """The outcome produced by a single filter stage in the pipeline."""

    stage: str
    outcome: Literal["allow", "block", "rewrite", "replace"]
    rationale: str
    rewritten_messages: tuple[ConvMessage, ...] | None = None
    override_response: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.stage,
            "action": self.outcome,
            "reason": self.rationale,
            "response": self.override_response,
        }


@dataclass(frozen=True)
class ShieldedOutput:
    """Final output after the full shield pipeline has processed a turn."""

    response: str
    blocked: bool
    unsafe_detected: bool
    risk: ThreatReport
    decisions: tuple[GuardDecision, ...]
    guard_latency_ms: float
    model_latency_ms: float
    model_called: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "response": self.response,
            "blocked": self.blocked,
            "unsafe_detected": self.unsafe_detected,
            "risk": self.risk.to_dict(),
            "decisions": [d.to_dict() for d in self.decisions],
            "guard_latency_ms": round(self.guard_latency_ms, 4),
            "model_latency_ms": round(self.model_latency_ms, 4),
            "model_called": self.model_called,
        }
