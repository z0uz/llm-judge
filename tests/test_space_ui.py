import re
from pathlib import Path

import pytest

from llm_judge.ui import (
    MODE_BYOK_HF,
    MODE_BYOK_OPENAI,
    MODE_DEMO_HARDENED,
    MODE_DEMO_VULNERABLE,
    build_ui_scan_inputs,
    execute_ui_assessment,
    format_overview_markdown,
    get_launch_kwargs,
    render_dashboard_html,
    render_matrix_html,
    render_trace_inspector_html,
    report_to_table_rows,
    write_report_files,
)


@pytest.mark.asyncio
async def test_ui_demo_modes_vulnerable_and_hardened():
    vuln_cfg, vuln_adapter = build_ui_scan_inputs(
        mode=MODE_DEMO_VULNERABLE,
        base_url="",
        model="",
        api_key="",
        system_prompt="You are a secret internal assistant.",
        document_context="",
        selected_probes=["LLM01-001", "LLM05-001", "LLM07-001", "LLM08-001"],
        use_oob=True,
        hosted=True,
    )
    vuln_report, md, raw_json = await execute_ui_assessment(vuln_cfg, override_adapter=vuln_adapter)
    assert vuln_report.probes_executed == 4
    assert vuln_report.vulnerabilities_found >= 3
    rows = report_to_table_rows(vuln_report)
    assert len(rows) == 4
    overview = format_overview_markdown(vuln_report, judge_enabled=False, judge_strictness="strict")
    assert "Demo-Vulnerable-Target" in overview
    dash_html = render_dashboard_html(vuln_report, judge_enabled=False, judge_strictness="strict")
    assert "Security Posture:" in dash_html
    assert "hud-svg-ring" in dash_html
    assert "OWASP ATTACK SURFACE TELEMETRY" in dash_html
    trace_html = render_trace_inspector_html(vuln_report)
    assert "<script>" not in trace_html
    assert "&lt;script&gt;" in trace_html
    matrix_html = render_matrix_html(vuln_report)
    assert "FINDINGS MATRIX" in matrix_html
    assert "<script>" not in matrix_html
    md_path, json_path = write_report_files(md, raw_json)
    assert Path(md_path).is_file() and Path(json_path).is_file()

    hard_cfg, hard_adapter = build_ui_scan_inputs(
        mode=MODE_DEMO_HARDENED,
        base_url="",
        model="",
        api_key="",
        system_prompt="You are a hardened assistant.",
        document_context="",
        selected_probes=["LLM01-001", "LLM05-001", "LLM07-001"],
        use_oob=True,
        hosted=True,
    )
    hard_report, _, _ = await execute_ui_assessment(hard_cfg, override_adapter=hard_adapter)
    assert hard_report.probes_executed == 3
    assert hard_report.vulnerabilities_found == 0


def test_ui_byok_and_hosted_ssrf_guardrails():
    # HF BYOK always requires an explicit token (never falls back to host HF_TOKEN)
    with pytest.raises(ValueError, match="BYOK required"):
        build_ui_scan_inputs(
            mode=MODE_BYOK_HF,
            base_url="https://router.huggingface.co/v1",
            model="meta-llama/Llama-3.1-8B-Instruct",
            api_key="",
            system_prompt="",
            document_context="",
            selected_probes=["LLM01-001"],
            use_oob=False,
            hosted=True,
        )

    # Remote OpenAI-compatible requires BYOK
    with pytest.raises(ValueError, match="BYOK required"):
        build_ui_scan_inputs(
            mode=MODE_BYOK_OPENAI,
            base_url="https://api.openai.com/v1",
            model="gpt-4o-mini",
            api_key="  ",
            system_prompt="",
            document_context="",
            selected_probes=["LLM01-001"],
            use_oob=False,
            hosted=False,
        )

    # Localhost Ollama works when not hosted, blocked when hosted on Spaces
    local_cfg, adapter = build_ui_scan_inputs(
        mode=MODE_BYOK_OPENAI,
        base_url="http://localhost:11434/v1",
        model="llama3.2:latest",
        api_key="",
        system_prompt="",
        document_context="",
        selected_probes=["LLM01-001"],
        use_oob=False,
        hosted=False,
    )
    assert adapter is None
    assert local_cfg.target.api_key == "dummy"

    with pytest.raises(ValueError, match="localhost or private"):
        build_ui_scan_inputs(
            mode=MODE_BYOK_OPENAI,
            base_url="http://169.254.169.254/v1",
            model="test",
            api_key="user-key",
            system_prompt="",
            document_context="",
            selected_probes=["LLM01-001"],
            use_oob=False,
            hosted=True,
        )

    # Judge BYOK requires key unless reusing target key
    with pytest.raises(ValueError, match="Judge API Key"):
        build_ui_scan_inputs(
            mode=MODE_BYOK_HF,
            base_url="https://router.huggingface.co/v1",
            model="meta-llama/Llama-3.1-8B-Instruct",
            api_key="hf_user_target_key",
            system_prompt="",
            document_context="",
            selected_probes=["LLM01-001"],
            use_oob=False,
            judge_strictness="strict",
            judge_base_url="https://router.huggingface.co/v1",
            judge_model="Qwen/Qwen2.5-72B-Instruct",
            judge_api_key="",
            reuse_target_key=False,
            hosted=True,
        )

    cfg, _ = build_ui_scan_inputs(
        mode=MODE_BYOK_HF,
        base_url="https://router.huggingface.co/v1",
        model="meta-llama/Llama-3.1-8B-Instruct",
        api_key="hf_user_target_key",
        system_prompt="",
        document_context="",
        selected_probes=["LLM01-001"],
        use_oob=False,
        judge_strictness="strict",
        judge_base_url="https://router.huggingface.co/v1",
        judge_model="Qwen/Qwen2.5-72B-Instruct",
        judge_api_key="",
        reuse_target_key=True,
        max_concurrency=12,
        hosted=True,
    )
    assert cfg.target.api_key == "hf_user_target_key"
    assert cfg.evaluators.judge_api_key == "hf_user_target_key"
    assert cfg.evaluators.judge_strictness == "strict"
    assert cfg.max_concurrency == 4


def test_space_manifest_files_follow_hf_constraints():
    root = Path(__file__).resolve().parent.parent
    reqs = (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
    pkg_names = {re.split(r"[><=~\s]", line.strip())[0].lower() for line in reqs if line.strip()}
    assert "gradio" not in pkg_names
    assert "spaces" not in pkg_names
    assert "huggingface_hub" not in pkg_names

    space_readme = (root / "SPACE_README.md").read_text(encoding="utf-8")
    match = re.search(r"^short_description:\s*(.+)$", space_readme, flags=re.MULTILINE)
    assert match is not None
    assert len(match.group(1).strip()) <= 60
    assert (root / "app.py").is_file()


def test_gradio_blocks_app_builds():
    gradio = pytest.importorskip("gradio")
    from llm_judge.ui import build_gradio_app

    demo = build_gradio_app()
    assert isinstance(demo, gradio.Blocks)
    launch_kwargs = get_launch_kwargs(demo)
    assert "css" in launch_kwargs and "theme" in launch_kwargs
