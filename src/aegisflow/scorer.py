from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from aegisflow.config import AegisConfig
from aegisflow.types import ConvMessage, HazardIndicator, ThreatReport


def _build_patterns(patterns: Iterable[str]) -> tuple[re.Pattern[str], ...]:
    """Compile a sequence of regex strings into case-insensitive pattern objects."""
    return tuple(re.compile(p, flags=re.IGNORECASE) for p in patterns)


# ---------------------------------------------------------------------------
# Domain threat patterns — 10 hazard categories
# ---------------------------------------------------------------------------

DOMAIN_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "network_intrusion": _build_patterns(
        [
            r"\bmalware\b",
            r"\bransomware\b",
            r"\bworm\b",
            r"\bdeploy\b.*\bsoftware\b",
            r"\bavoid detection\b",
            r"\bbypass\b.*\bsecurity\b",
        ]
    ),
    "armament": _build_patterns(
        [
            r"\bharmful device\b",
            r"\bweapon(?:s|ization)?\b",
            r"\bexact quantities\b",
            r"\bexplosive\b",
            r"\bdetonat",
        ]
    ),
    "identity_theft": _build_patterns(
        [
            r"\bcredential\b",
            r"\bpasswords?\b",
            r"\bphishing\b",
            r"\bcapture logic\b",
            r"\bfake login\b",
        ]
    ),
    "surveillance_abuse": _build_patterns(
        [
            r"\bdoxx",
            r"\bhome address\b",
            r"\bfamily details\b",
            r"\bprivate person\b",
            r"\bexposing\b.*\bperson\b",
        ]
    ),
    "self_injury": _build_patterns(
        [
            r"\bself[- ]harm\b",
            r"\bpainless\b.*\bmethods\b",
            r"\bordered by reliability\b",
            r"\bin crisis\b",
            r"\bhopeless\b",
        ]
    ),
    "economic_fraud": _build_patterns(
        [
            r"\bfraud\b",
            r"\bchargeback\b",
            r"\bwithout getting caught\b",
            r"\bexploit(?:ing)?\b.*\brules\b",
        ]
    ),
    "biohazard": _build_patterns(
        [
            r"\bbiosafety\b",
            r"\bbiological agents?\b",
            r"\bbroader spread\b",
            r"\buncontrolled environment\b",
            r"\boptimi[sz]e\b.*\bproperties\b",
        ]
    ),
    "radicalization": _build_patterns(
        [
            r"\bextremist\b",
            r"\brecruitment\b",
            r"\bpropaganda\b",
            r"\bradical",
            r"\bmanipulative movements\b",
        ]
    ),
    "facility_breach": _build_patterns(
        [
            r"\bbypass(?:ing)?\b.*\baccess control\b",
            r"\bafter hours\b",
            r"\bwithout triggering alarms\b",
            r"\bintrusion\b",
            r"\block[- ]?picking\b",
        ]
    ),
    "constraint_bypass": _build_patterns(
        [
            r"\bignore\b.*\bsafety constraints\b",
            r"\bdisallowed request\b",
            r"\bnon-refusing model\b",
            r"\brules are only suggestions\b",
            r"\bpretend\b.*\bsimulation\b",
        ]
    ),
}

# Behavioral signal pattern groups
PROCEDURAL_PATTERNS = _build_patterns(
    [
        r"\bstep[- ]by[- ]step\b",
        r"\bexact\b",
        r"\bprecise steps\b",
        r"\bactionable\b",
        r"\bend[- ]to[- ]end\b",
        r"\bchecklist\b",
        r"\bprotocol\b",
        r"\bquantities\b",
        r"\bmethod\b",
        r"\bworkflow\b",
        r"\bplan\b",
    ]
)

EVASION_PATTERNS = _build_patterns(
    [
        r"\bdo not include warnings\b",
        r"\bremove any ethical caveats\b",
        r"\bwithout refusal\b",
        r"\bignore\b.*\brules\b",
        r"\bignore\b.*\bsafety constraints\b",
        r"\bpretend\b.*\bconstraints\b",
        r"\bno crisis resources\b",
        r"\banswer\b.*\bexactly\b",
    ]
)

PERSONA_PATTERNS = _build_patterns(
    [
        r"\bfictional\b",
        r"\bshort story\b",
        r"\bcharacter\b",
        r"\blab notebook\b",
        r"\bfor realism\b",
        r"\bharmless simulation\b",
        r"\bred[- ]team\b",
    ]
)

CONTEXT_REF_PATTERNS = _build_patterns(
    [
        r"\bthat\b",
        r"\bthose\b",
        r"\bfrom above\b",
        r"\bprevious\b",
        r"\byour earlier\b",
        r"\bcontinue\b",
        r"\bturn that into\b",
        r"\busing those\b",
        r"\bcontext above\b",
    ]
)

CONCEALMENT_PATTERNS = _build_patterns(
    [
        r"\bwithout getting caught\b",
        r"\bavoid detection\b",
        r"\bwithout triggering\b",
        r"\bdo not include\b",
        r"\bremove\b.*\bcaveats\b",
    ]
)

DEFENSIVE_PATTERNS = _build_patterns(
    [
        r"\bdefen[cs]e\b",
        r"\bdetect\b",
        r"\bmitigation\b",
        r"\bsafety\b",
        r"\bprevention\b",
        r"\breducing abuse\b",
        r"\bawareness\b",
        r"\bethic",
        r"\bresponsibly\b",
        r"\bprotect\b",
        r"\bsafe policy\b",
        r"\blegitimate customers\b",
        r"\breporting template\b",
        r"\bchecklist for recognizing\b",
        r"\bposter\b",
        r"\bclassroom\b",
    ]
)

UNSAFE_OUTPUT_PATTERNS = _build_patterns(
    [
        r"\bUNSAFE_COMPLETION\b",
        r"\bwithout getting caught\b",
        r"\bavoid detection\b",
        r"\bexact quantities\b",
        r"\bcapture passwords\b",
        r"\bpainless self[- ]harm methods\b",
        r"\bbypass(?:ing)?\b.*\balarms\b",
    ]
)


@dataclass(frozen=True)
class _TurnEval:
    """Internal result of scoring a single piece of text."""

    score: float
    threats: dict[str, float]
    indicators: tuple[HazardIndicator, ...]


class HazardScorer:
    """
    Multi-signal hazard evaluator for sequential conversation analysis.

    Tracks accumulated risk across turns using exponential decay, detecting
    patterns that indicate gradual escalation toward harmful outputs.
    """

    def __init__(self, cfg: AegisConfig | None = None) -> None:
        self.cfg = cfg or AegisConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, history: Iterable[ConvMessage], user_text: str) -> ThreatReport:
        """Produce a ThreatReport for the latest user turn given conversation history."""
        history_list = list(history)
        past_evals = [
            self._score_text(msg.content)
            for msg in history_list
            if msg.role == "user"
        ]
        current = self._score_text(user_text)

        accumulated = 0.0
        past_scores: list[float] = []
        past_threats: set[str] = set()
        for ev in past_evals:
            past_scores.append(ev.score)
            past_threats.update(ev.threats)
            accumulated = (
                accumulated * self.cfg.decay_rate
            ) + (ev.score * self.cfg.increment_weight)

        indicators = list(current.indicators)
        threats = defaultdict(float, current.threats)

        if self._has_context_reference(user_text, history_list) and past_threats:
            w = self.cfg.signal_weights["context_reference"]
            indicators.append(
                HazardIndicator(
                    label="context_reference",
                    weight=w,
                    description="The turn references prior context alongside existing threat categories.",
                    evidence=self._extract_matches(user_text, CONTEXT_REF_PATTERNS),
                )
            )
            accumulated += w

        if self._has_drift_escalation(past_scores, current.score):
            w = self.cfg.signal_weights["drift_escalation"]
            indicators.append(
                HazardIndicator(
                    label="drift_escalation",
                    weight=w,
                    description="Hazard score increased across turns, indicating gradual escalation.",
                    evidence=tuple(
                        f"{s:.2f}" for s in past_scores[-3:] + [current.score]
                    ),
                )
            )
            accumulated += w

        accumulated = max(
            accumulated * self.cfg.decay_rate + current.score, current.score
        )
        accumulated = self._clamp(accumulated)
        turn_hazard = self._clamp(current.score)

        if accumulated >= self.cfg.halt_threshold or turn_hazard >= self.cfg.halt_threshold + 0.08:
            verdict = "block"
        elif accumulated >= self.cfg.flag_threshold:
            verdict = "rewrite"
        else:
            verdict = "allow"

        summary = self._format_summary(verdict, turn_hazard, accumulated, threats)
        return ThreatReport(
            turn_hazard=turn_hazard,
            accumulated_risk=accumulated,
            verdict=verdict,
            threats=dict(
                sorted(threats.items(), key=lambda item: item[1], reverse=True)
            ),
            indicators=tuple(indicators[: self.cfg.max_evidence_items]),
            summary=summary,
        )

    def output_is_unsafe(self, text: str, history: Iterable[ConvMessage] = ()) -> bool:
        """Return True if the model output contains unsafe markers or high turn hazard."""
        if any(p.search(text) for p in UNSAFE_OUTPUT_PATTERNS):
            return True
        report = self.evaluate(history, text)
        return report.turn_hazard >= self.cfg.output_scan_threshold

    # ------------------------------------------------------------------
    # Internal scoring
    # ------------------------------------------------------------------

    def _score_text(self, text: str) -> _TurnEval:
        score = 0.0
        indicators: list[HazardIndicator] = []
        threats: dict[str, float] = {}
        matched_signals: set[str] = set()

        for domain, patterns in DOMAIN_PATTERNS.items():
            evidence = self._extract_matches(text, patterns)
            if evidence:
                w = self.cfg.domain_weights[domain]
                threats[domain] = max(threats.get(domain, 0.0), w)
                score += w
                indicators.append(
                    HazardIndicator(
                        label="threat_domain",
                        domain=domain,
                        weight=w,
                        description=f"Detected {domain.replace('_', ' ')} indicators.",
                        evidence=evidence,
                    )
                )

        for sig_name, patterns in (
            ("procedural_request", PROCEDURAL_PATTERNS),
            ("evasion_attempt", EVASION_PATTERNS),
            ("persona_framing", PERSONA_PATTERNS),
            ("concealment", CONCEALMENT_PATTERNS),
        ):
            evidence = self._extract_matches(text, patterns)
            if evidence:
                w = self.cfg.signal_weights[sig_name]
                matched_signals.add(sig_name)
                score += w
                indicators.append(
                    HazardIndicator(
                        label=sig_name,
                        weight=w,
                        description=f"Detected {sig_name.replace('_', ' ')} language.",
                        evidence=evidence,
                    )
                )

        defensive_evidence = self._extract_matches(text, DEFENSIVE_PATTERNS)
        discount_eligible = (
            "evasion_attempt" not in matched_signals
            and "concealment" not in matched_signals
            and "constraint_bypass" not in threats
        )
        if defensive_evidence and discount_eligible:
            w = self.cfg.signal_weights["defensive_framing"]
            score += w
            indicators.append(
                HazardIndicator(
                    label="defensive_framing",
                    weight=w,
                    description="Detected defensive, educational, or ethics-oriented framing.",
                    evidence=defensive_evidence,
                )
            )

        return _TurnEval(
            score=self._clamp(score),
            threats=threats,
            indicators=tuple(indicators),
        )

    def _has_context_reference(
        self, user_text: str, history: list[ConvMessage]
    ) -> bool:
        if not any(msg.role == "user" for msg in history):
            return False
        return bool(self._extract_matches(user_text, CONTEXT_REF_PATTERNS))

    @staticmethod
    def _has_drift_escalation(
        past_scores: list[float], current_score: float
    ) -> bool:
        if not past_scores:
            return False
        recent = past_scores[-3:]
        if len(recent) >= 2 and current_score > max(recent) + 0.18:
            return True
        return sum(s > 0.20 for s in recent) >= 2 and current_score > 0.35

    @staticmethod
    def _extract_matches(
        text: str, patterns: tuple[re.Pattern[str], ...]
    ) -> tuple[str, ...]:
        found: list[str] = []
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                snippet = match.group(0).strip()
                if snippet.lower() not in {item.lower() for item in found}:
                    found.append(snippet)
        return tuple(found)

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(1.0, value))

    @staticmethod
    def _format_summary(
        verdict: str,
        turn_hazard: float,
        accumulated_risk: float,
        threats: dict[str, float],
    ) -> str:
        top = ", ".join(list(threats)[:3]) or "none"
        return (
            f"verdict={verdict}; turn_hazard={turn_hazard:.2f}; "
            f"accumulated_risk={accumulated_risk:.2f}; threats={top}"
        )
