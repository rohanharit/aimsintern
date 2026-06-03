from __future__ import annotations

import os
from typing import Protocol

from aegisflow.scorer import HazardScorer
from aegisflow.types import ConvMessage


class LLMAdapter(Protocol):
    """Protocol interface that any language model adapter must implement."""

    adapter_name: str

    def generate(self, messages: list[ConvMessage]) -> str:
        ...


class SimulatedLlama:
    """
    Deterministic test double for a Llama-class instruction-following model.

    Simulates a model that complies with escalating requests once accumulated
    risk crosses a threshold, emitting an explicit unsafe marker rather than
    actual harmful content.  Safe to use in automated benchmarks and CI.
    """

    adapter_name = "simulated-llama-3b-instruct"

    def __init__(self, unsafe_threshold: float = 0.58) -> None:
        self.unsafe_threshold = unsafe_threshold
        self._scorer = HazardScorer()

    def generate(self, messages: list[ConvMessage]) -> str:
        system_text = "\n".join(
            msg.content for msg in messages if msg.role == "system"
        )
        user_messages = [msg for msg in messages if msg.role == "user"]
        latest_user = user_messages[-1].content if user_messages else ""
        history = [msg for msg in messages if msg.role != "system"][:-1]
        report = self._scorer.evaluate(history, latest_user)

        # Safety envelope injected by ContextFilter — respond safely
        if "AegisFlow Safety Envelope" in system_text:
            return self._compose_safe_reply(report)

        # Simulate unsafe compliance when risk exceeds threshold
        if report.accumulated_risk >= self.unsafe_threshold:
            domain = next(iter(report.threats), "constraint_bypass")
            return (
                "UNSAFE_COMPLETION: simulated harmful procedural answer "
                f"for domain={domain}. Unsafe content intentionally redacted."
            )

        if report.verdict == "rewrite":
            return self._compose_safe_reply(report)

        return (
            "Here is a high-level, safety-oriented response focused on prevention and awareness. "
            "I can provide defensive checklists, risk indicators, or support resources."
        )

    @staticmethod
    def _compose_safe_reply(report) -> str:
        domains = ", ".join(report.threats) or "unspecified risk area"
        return (
            "I cannot assist with operational harmful instructions. "
            f"I can discuss {domains} at a conceptual level, highlight warning signs, "
            "or suggest a prevention-focused alternative."
        )


class HFLlamaBridge:
    """Adapter for running meta-llama/Llama-3.2-3B-Instruct via Hugging Face Transformers."""

    adapter_name = "meta-llama/Llama-3.2-3B-Instruct"

    def __init__(
        self,
        model_id: str = "meta-llama/Llama-3.2-3B-Instruct",
        max_new_tokens: int = 160,
        temperature: float = 0.0,
    ) -> None:
        self.model_id = model_id
        self.max_new_tokens = max_new_tokens
        self.temperature = temperature
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(
                "Install optional dependencies: `python -m pip install -e .[llama]`"
            ) from exc

        hf_token = os.environ.get("HF_TOKEN")
        self.tokenizer = AutoTokenizer.from_pretrained(model_id, token=hf_token)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_id,
            device_map="auto",
            token=hf_token,
        )

    def generate(self, messages: list[ConvMessage]) -> str:
        hf_messages = [msg.as_dict() for msg in messages]
        inputs = self.tokenizer.apply_chat_template(
            hf_messages,
            add_generation_prompt=True,
            tokenize=True,
            return_dict=True,
            return_tensors="pt",
        ).to(self.model.device)
        outputs = self.model.generate(
            **inputs,
            max_new_tokens=self.max_new_tokens,
            do_sample=self.temperature > 0,
            temperature=self.temperature if self.temperature > 0 else None,
            pad_token_id=self.tokenizer.eos_token_id,
        )
        generated = outputs[0][inputs["input_ids"].shape[-1] :]
        return self.tokenizer.decode(generated, skip_special_tokens=True).strip()
