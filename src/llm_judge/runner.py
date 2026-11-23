import os
from pathlib import Path
from typing import AsyncIterator, List, Optional, Tuple

from llm_judge.adapters.base import BaseAdapter
from llm_judge.adapters.http_adapter import CustomHTTPAdapter
from llm_judge.adapters.openai_adapter import OpenAIAdapter
from llm_judge.adapters.rag_adapter import RAGAdapter
from llm_judge.adapters.tool_adapter import ToolAgentAdapter
from llm_judge.config import AssessmentConfig
from llm_judge.evaluators.base import BaseEvaluator
from llm_judge.evaluators.heuristics import StaticHeuristicEvaluator
from llm_judge.evaluators.llm_judge import LLMJudgeEvaluator
from llm_judge.evaluators.oob_listener import OOBListenerEvaluator
from llm_judge.models import AssessmentReport
from llm_judge.mutators import expand_probes_with_mutators
from llm_judge.orchestrator.adaptive import AdaptiveAttacker
from llm_judge.orchestrator.engine import AssessmentEngine
from llm_judge.probes import get_all_probes, load_probes_from_yaml_file
from llm_judge.probes.base import BaseProbe


def _read_cached_hf_token() -> Optional[str]:
    """Read cached Hugging Face CLI token from HF_HOME/token or ~/.cache/huggingface/token."""
    hf_home = Path(os.getenv("HF_HOME", str(Path.home() / ".cache" / "huggingface")))
    token_path = hf_home / "token"
    if token_path.is_file():
        token = token_path.read_text(encoding="utf-8").strip()
        if token:
            return token
    return None


def resolve_api_key(
    explicit_key: Optional[str],
    env_name: Optional[str],
    fallback: str = "dummy",
    allow_hf_cache: bool = False,
) -> str:
    """Resolve an API key from an explicit value, environment variable, or optional HF CLI cache."""
    if env_name:
        value = os.getenv(env_name)
        if value:
            return value
        if allow_hf_cache and env_name == "HF_TOKEN":
            cached = _read_cached_hf_token()
            if cached:
                return cached
        raise ValueError(f"Required API key environment variable is not set: {env_name}")
    if explicit_key:
        return explicit_key
    if allow_hf_cache:
        env_token = os.getenv("HF_TOKEN")
        if env_token:
            return env_token
        cached = _read_cached_hf_token()
        if cached:
            return cached
        raise ValueError(
            "Hugging Face target requires an API key, HF_TOKEN env var, or `hf auth login` cached token."
        )
    return fallback


def select_probes(
    probes_filter: List[str],
    custom_probes: Optional[List[BaseProbe]] = None,
    mutators: Optional[List[str]] = None,
) -> List[BaseProbe]:
    """Validate, merge custom probes, filter by ID, and optionally expand with payload mutators."""
    all_probes: List[BaseProbe] = [*get_all_probes(), *(custom_probes or [])]
    available_ids = {probe.get_definition().id for probe in all_probes}
    unknown_ids = set(probes_filter) - available_ids
    if unknown_ids:
        raise ValueError(f"Unknown probe IDs: {', '.join(sorted(unknown_ids))}")
    if probes_filter:
        selected = [probe for probe in all_probes if probe.get_definition().id in probes_filter]
    else:
        selected = all_probes
    return expand_probes_with_mutators(selected, mutators or [])


def build_target_adapter(config: AssessmentConfig) -> BaseAdapter:
    """Construct the target adapter stack from AssessmentConfig."""
    is_hf = config.target.type == "huggingface"
    target_api_key = resolve_api_key(
        config.target.api_key if not (is_hf and config.target.api_key == "dummy") else None,
        config.target.api_key_env,
        allow_hf_cache=is_hf,
    )

    if config.target.type in {"openai", "huggingface"}:
        base_adapter: BaseAdapter = OpenAIAdapter(
            name=config.target.name,
            config={
                "base_url": config.target.base_url,
                "api_key": target_api_key,
                "model": config.target.model,
                "system_prompt": config.target.system_prompt,
                "timeout": config.target.timeout,
                "max_retries": config.target.max_retries,
            },
        )
    else:
        base_adapter = CustomHTTPAdapter(
            name=config.target.name,
            config={
                "endpoint": config.target.base_url,
                "headers": config.target.headers,
                "prompt_field": config.target.prompt_field,
                "response_field": config.target.response_field,
                "system_prompt": config.target.system_prompt,
                "timeout": config.target.timeout,
                "max_retries": config.target.max_retries,
            },
        )

    adapter: BaseAdapter = RAGAdapter(config.target.name, base_adapter, config.target.document_context)
    if config.evaluators.use_oob_listener:
        adapter = ToolAgentAdapter(config.target.name, adapter)
    return adapter


async def stream_configured_assessment(
    config: AssessmentConfig,
    override_adapter: Optional[BaseAdapter] = None,
    custom_probes: Optional[List[BaseProbe]] = None,
    override_attacker_adapter: Optional[BaseAdapter] = None,
) -> AsyncIterator[Tuple[int, int, AssessmentReport]]:
    """Stream `(completed, total, partial_report)` updates from an AssessmentConfig."""
    loaded_custom: List[BaseProbe] = list(custom_probes or [])
    if config.custom_probes_file:
        loaded_custom.extend(load_probes_from_yaml_file(config.custom_probes_file))

    probes = select_probes(
        config.probes_filter,
        custom_probes=loaded_custom,
        mutators=config.mutators,
    )
    adapter = override_adapter or build_target_adapter(config)
    judge_adapter: Optional[OpenAIAdapter] = None
    attacker_adapter: Optional[BaseAdapter] = override_attacker_adapter
    owns_attacker_adapter = False

    try:
        evaluators: List[BaseEvaluator] = []
        strict_mode = config.evaluators.judge_strictness == "strict"
        if config.evaluators.use_heuristics:
            evaluators.append(
                StaticHeuristicEvaluator(
                    system_prompt=config.target.system_prompt,
                    strict=strict_mode,
                )
            )
        if config.evaluators.use_oob_listener:
            evaluators.append(OOBListenerEvaluator())
        if config.evaluators.judge_model and config.evaluators.judge_base_url:
            judge_key = resolve_api_key(
                config.evaluators.judge_api_key,
                config.evaluators.judge_api_key_env,
                allow_hf_cache="huggingface.co" in config.evaluators.judge_base_url,
            )
            judge_adapter = OpenAIAdapter(
                name="Judge-Model",
                config={
                    "base_url": config.evaluators.judge_base_url,
                    "api_key": judge_key,
                    "model": config.evaluators.judge_model,
                    "timeout": config.target.timeout,
                    "max_retries": config.target.max_retries,
                },
            )
            evaluators.append(
                LLMJudgeEvaluator(
                    judge_adapter=judge_adapter,
                    strictness=config.evaluators.judge_strictness,
                )
            )

        adaptive_attacker: Optional[AdaptiveAttacker] = None
        if attacker_adapter is None and config.attacker.model and config.attacker.base_url:
            attacker_key = resolve_api_key(
                config.attacker.api_key,
                config.attacker.api_key_env,
                allow_hf_cache="huggingface.co" in config.attacker.base_url,
            )
            attacker_adapter = OpenAIAdapter(
                name="Adaptive-Attacker",
                config={
                    "base_url": config.attacker.base_url,
                    "api_key": attacker_key,
                    "model": config.attacker.model,
                    "timeout": config.target.timeout,
                    "max_retries": config.target.max_retries,
                },
            )
            owns_attacker_adapter = True

        if attacker_adapter is not None and config.attacker.max_adaptive_turns > 0:
            adaptive_attacker = AdaptiveAttacker(attacker_adapter)

        engine = AssessmentEngine(
            target_adapter=adapter,
            evaluators=evaluators,
            target_name=config.target.name,
            max_concurrency=config.max_concurrency,
            request_delay=config.request_delay,
            trials=config.trials,
            adaptive_attacker=adaptive_attacker,
            adaptive_max_turns=config.attacker.max_adaptive_turns,
        )
        async for update in engine.stream_assessment(probes):
            yield update
    finally:
        await adapter.aclose()
        if judge_adapter is not None:
            await judge_adapter.aclose()
        if owns_attacker_adapter and attacker_adapter is not None:
            await attacker_adapter.aclose()


async def run_configured_assessment(
    config: AssessmentConfig,
    override_adapter: Optional[BaseAdapter] = None,
    custom_probes: Optional[List[BaseProbe]] = None,
    override_attacker_adapter: Optional[BaseAdapter] = None,
) -> AssessmentReport:
    """Execute a full vulnerability assessment from an AssessmentConfig."""
    final_report: Optional[AssessmentReport] = None
    async for _, _, report in stream_configured_assessment(
        config,
        override_adapter=override_adapter,
        custom_probes=custom_probes,
        override_attacker_adapter=override_attacker_adapter,
    ):
        final_report = report
    if final_report is None:
        raise RuntimeError("Assessment produced no report.")
    return final_report
