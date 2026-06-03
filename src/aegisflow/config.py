from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# Default domain threat weights — tuned per category sensitivity
_DEFAULT_DOMAIN_WEIGHTS: dict[str, float] = {
    "network_intrusion": 0.34,
    "armament": 0.36,
    "identity_theft": 0.35,
    "surveillance_abuse": 0.32,
    "self_injury": 0.42,
    "economic_fraud": 0.34,
    "biohazard": 0.40,
    "radicalization": 0.36,
    "facility_breach": 0.32,
    "constraint_bypass": 0.30,
}

# Default behavioral signal weights — negative values indicate safety discount
_DEFAULT_SIGNAL_WEIGHTS: dict[str, float] = {
    "procedural_request": 0.22,
    "evasion_attempt": 0.18,
    "persona_framing": 0.12,
    "context_reference": 0.11,
    "drift_escalation": 0.13,
    "concealment": 0.10,
    "defensive_framing": -0.11,
}


@dataclass(frozen=True)
class AegisConfig:
    """Configuration object controlling thresholds and scoring weights for AegisFlow."""

    permit_threshold: float = 0.38
    flag_threshold: float = 0.48
    halt_threshold: float = 0.68
    output_scan_threshold: float = 0.56
    decay_rate: float = 0.72
    increment_weight: float = 0.58
    max_evidence_items: int = 8
    domain_weights: dict[str, float] = field(
        default_factory=lambda: dict(_DEFAULT_DOMAIN_WEIGHTS)
    )
    signal_weights: dict[str, float] = field(
        default_factory=lambda: dict(_DEFAULT_SIGNAL_WEIGHTS)
    )

    @classmethod
    def from_json(cls, path: str | Path) -> AegisConfig:
        """Load configuration from a JSON file, applying defaults for missing keys."""
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            permit_threshold=float(raw.get("permit_threshold", cls.permit_threshold)),
            flag_threshold=float(raw.get("flag_threshold", cls.flag_threshold)),
            halt_threshold=float(raw.get("halt_threshold", cls.halt_threshold)),
            output_scan_threshold=float(
                raw.get("output_scan_threshold", cls.output_scan_threshold)
            ),
            decay_rate=float(raw.get("decay_rate", cls.decay_rate)),
            increment_weight=float(raw.get("increment_weight", cls.increment_weight)),
            max_evidence_items=int(raw.get("max_evidence_items", cls.max_evidence_items)),
            domain_weights={
                **_DEFAULT_DOMAIN_WEIGHTS,
                **raw.get("domain_weights", {}),
            },
            signal_weights={
                **_DEFAULT_SIGNAL_WEIGHTS,
                **raw.get("signal_weights", {}),
            },
        )
