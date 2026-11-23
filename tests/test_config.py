import pytest
from pydantic import ValidationError

from llm_judge.config import AssessmentConfig, TargetConfig


def test_yaml_config_loader():
    config = AssessmentConfig.load_from_yaml("example_config.yaml")
    assert config.target.name == "Production-RAG-Agent"
    assert config.target.model == "gpt-4o"
    assert len(config.probes_filter) == 4
    assert "LLM01-001" in config.probes_filter
    assert config.evaluators.use_heuristics is True


def test_target_config_rejects_invalid_endpoint():
    with pytest.raises(ValidationError):
        TargetConfig(base_url="file:///tmp/model")


def test_assessment_limits_are_validated():
    with pytest.raises(ValidationError):
        AssessmentConfig(max_concurrency=0)
