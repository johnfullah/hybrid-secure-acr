"""Base class for all gates."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import GateResult, ReviewContext


class Gate(ABC):
    gate_id: str = ""
    gate_name: str = ""

    @abstractmethod
    def run(self, ctx: ReviewContext) -> GateResult:  # pragma: no cover - interface
        ...
