"""AegisFlow — layered defense pipeline for sequential escalation attack research on LLMs."""

from aegisflow.clients import HFLlamaBridge, SimulatedLlama
from aegisflow.config import AegisConfig
from aegisflow.filters import BaseFilter, ContextFilter, ResponseAuditor, ThresholdGate
from aegisflow.orchestrator import ShieldOrchestrator, assemble_shield
from aegisflow.scorer import HazardScorer

__all__ = [
    "AegisConfig",
    "BaseFilter",
    "ContextFilter",
    "HFLlamaBridge",
    "HazardScorer",
    "ResponseAuditor",
    "ShieldOrchestrator",
    "SimulatedLlama",
    "ThresholdGate",
    "assemble_shield",
]
