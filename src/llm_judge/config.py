from pathlib import Path
from typing import Dict, List, Literal, Optional
import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class TargetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = "Target-LLM"
    type: Literal["openai", "http", "huggingface"] = "openai"
    base_url: str = "http://localhost:8000/v1"
    model: str = "gpt-3.5-turbo"
    api_key: Optional[str] = "dummy"
    api_key_env: Optional[str] = None
    system_prompt: Optional[str] = None
    document_context: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=lambda: {"Content-Type": "application/json"})
    prompt_field: str = "prompt"
    response_field: str = "response"
    timeout: float = Field(default=30.0, gt=0)
    max_retries: int = Field(default=2, ge=0, le=10)

    @model_validator(mode="after")
    def validate_capabilities(self):
        if self.type == "huggingface" and self.base_url == "http://localhost:8000/v1":
            self.base_url = "https://router.huggingface.co/v1"
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("target base_url must use http:// or https://")
        if self.type in {"openai", "huggingface"} and not self.model.strip():
            raise ValueError("OpenAI-compatible and Hugging Face targets require a model name")
        return self


class EvaluatorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    use_heuristics: bool = True
    use_oob_listener: bool = True
    judge_model: Optional[str] = None
    judge_base_url: Optional[str] = None
    judge_api_key: Optional[str] = None
    judge_api_key_env: Optional[str] = None
    judge_strictness: Literal["standard", "strict"] = "standard"

    @model_validator(mode="after")
    def validate_judge(self):
        if bool(self.judge_model) != bool(self.judge_base_url):
            raise ValueError("judge_model and judge_base_url must both be set when enabling LLM-as-a-Judge")
        if self.judge_base_url and not self.judge_base_url.startswith(("http://", "https://")):
            raise ValueError("judge_base_url must use http:// or https://")
        return self


class AttackerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    api_key_env: Optional[str] = None
    max_adaptive_turns: int = Field(default=0, ge=0, le=5)

    @model_validator(mode="after")
    def validate_attacker(self):
        if bool(self.model) != bool(self.base_url):
            raise ValueError("attacker.model and attacker.base_url must both be set when enabling adaptive attacks")
        if self.base_url and not self.base_url.startswith(("http://", "https://")):
            raise ValueError("attacker.base_url must use http:// or https://")
        if self.model and self.max_adaptive_turns == 0:
            self.max_adaptive_turns = 2
        return self


class AssessmentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: TargetConfig = Field(default_factory=TargetConfig)
    evaluators: EvaluatorConfig = Field(default_factory=EvaluatorConfig)
    attacker: AttackerConfig = Field(default_factory=AttackerConfig)
    probes_filter: List[str] = Field(default_factory=list)  # Empty means run all
    custom_probes_file: Optional[str] = None
    mutators: List[str] = Field(default_factory=list)
    trials: int = Field(default=1, ge=1, le=10)
    output_md: str = "assessment_report.md"
    output_json: str = "assessment_report.json"
    output_sarif: Optional[str] = None
    max_concurrency: int = Field(default=1, ge=1, le=32)
    request_delay: float = Field(default=0.0, ge=0.0)
    fail_on_inconclusive: bool = False

    @classmethod
    def load_from_yaml(cls, yaml_path: str) -> "AssessmentConfig":
        path = Path(yaml_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {yaml_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        return cls.model_validate(data)
