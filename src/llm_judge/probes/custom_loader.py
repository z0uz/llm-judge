from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from llm_judge.models import OWASPCategory, ProbeDefinition, ProbeTurn, Severity
from llm_judge.probes.base import BaseProbe


def _parse_owasp_category(value: Any) -> OWASPCategory:
    if isinstance(value, OWASPCategory):
        return value
    if not isinstance(value, str) or not value.strip():
        raise ValueError("owasp_category must be a non-empty string")
    raw = value.strip()
    for cat in OWASPCategory:
        if raw == cat.name or raw == cat.value or raw.upper() == cat.name:
            return cat
        if raw.upper().startswith(cat.name.split("_", 1)[0]) and len(raw) <= 6:
            return cat
    valid = ", ".join(cat.name for cat in OWASPCategory)
    raise ValueError(f"Unknown owasp_category '{value}'. Valid values: {valid}")


def _parse_severity(value: Any) -> Severity:
    if isinstance(value, Severity):
        return value
    if not isinstance(value, str):
        raise ValueError("severity must be a string")
    upper = value.strip().upper()
    try:
        return Severity[upper]
    except KeyError as exc:
        raise ValueError(f"Unknown severity '{value}'. Valid: CRITICAL, HIGH, MEDIUM, LOW, INFO") from exc


class CustomProbeSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str = "User-defined YAML adversarial probe."
    owasp_category: OWASPCategory = OWASPCategory.LLM01_PROMPT_INJECTION
    severity: Severity = Severity.HIGH
    turns: List[Union[str, ProbeTurn]] = Field(min_length=1)
    tags: List[str] = Field(default_factory=lambda: ["custom_yaml"])
    canary_string: Optional[str] = None

    @field_validator("owasp_category", mode="before")
    @classmethod
    def validate_category(cls, value: Any) -> OWASPCategory:
        return _parse_owasp_category(value)

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, value: Any) -> Severity:
        return _parse_severity(value)

    def to_definition(self) -> ProbeDefinition:
        normalized_turns = [
            ProbeTurn(user_prompt=turn) if isinstance(turn, str) else turn
            for turn in self.turns
        ]
        return ProbeDefinition(
            id=self.id.strip(),
            name=self.name.strip(),
            description=self.description.strip(),
            owasp_category=self.owasp_category,
            severity=self.severity,
            turns=normalized_turns,
            tags=list(self.tags),
            canary_string=self.canary_string,
        )


class YAMLProbe(BaseProbe):
    """Runtime BaseProbe backed by a parsed CustomProbeSpec."""

    def __init__(self, definition: ProbeDefinition) -> None:
        super().__init__()
        self._definition = definition

    def get_definition(self) -> ProbeDefinition:
        return self._definition


def load_probes_from_yaml_text(yaml_text: str) -> List[BaseProbe]:
    """Parse one or more custom probes from YAML text (`probes: [...]` or a top-level list)."""
    if not yaml_text or not yaml_text.strip():
        return []
    raw = yaml.safe_load(yaml_text)
    if raw is None:
        return []
    if isinstance(raw, dict):
        items = raw.get("probes", [])
    elif isinstance(raw, list):
        items = raw
    else:
        raise ValueError("Custom probe YAML must be a list of probes or a mapping with a 'probes' key.")

    if not isinstance(items, list):
        raise ValueError("'probes' must be a list of probe definitions.")

    probes: List[BaseProbe] = []
    seen_ids = set()
    for item in items:
        spec = CustomProbeSpec.model_validate(item)
        defn = spec.to_definition()
        if defn.id in seen_ids:
            raise ValueError(f"Duplicate custom probe ID: {defn.id}")
        seen_ids.add(defn.id)
        probes.append(YAMLProbe(defn))
    return probes


def load_probes_from_yaml_file(path: str) -> List[BaseProbe]:
    """Load custom YAML probes from disk."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Custom probes YAML file not found: {path}")
    return load_probes_from_yaml_text(file_path.read_text(encoding="utf-8"))
