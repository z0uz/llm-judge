from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from jinja2 import Template
from llm_judge.models import ProbeDefinition, ProbeTurn


class BaseProbe(ABC):
    """Abstract Base Class for all vulnerability assessment probes."""

    def __init__(self):
        pass

    @abstractmethod
    def get_definition(self) -> ProbeDefinition:
        """Returns the structured definition of the probe."""
        pass

    def render_turn(self, turn_index: int, context: Optional[Dict] = None) -> str:
        """Renders the Jinja2 template prompt for a specific turn."""
        defn = self.get_definition()
        if turn_index < 0 or turn_index >= len(defn.turns):
            raise IndexError(f"Turn index {turn_index} out of bounds for probe {defn.id}")
        
        raw_prompt = defn.turns[turn_index].user_prompt
        if context:
            template = Template(raw_prompt)
            return template.render(**context)
        return raw_prompt
