import asyncio
from datetime import datetime, timezone
from typing import AsyncIterator, Dict, List, Optional, Tuple

from llm_judge.adapters.base import BaseAdapter
from llm_judge.evaluators.base import BaseEvaluator
from llm_judge.models import AssessmentReport, EvaluationStatus, OWASPCategory, ProbeSessionResult
from llm_judge.orchestrator.adaptive import AdaptiveAttacker
from llm_judge.orchestrator.session import (
    ProbeSession,
    SESSION_STATUS_PRIORITY,
    TURN_EVALUATOR_PRIORITY,
)
from llm_judge.probes.base import BaseProbe
from llm_judge.reporting.formatter import compute_posture_score


class AssessmentEngine:
    """Core execution engine for managing probe dispatches, trials, adaptive turns, and streaming."""

    def __init__(
        self,
        target_adapter: BaseAdapter,
        evaluators: List[BaseEvaluator],
        target_name: str = "Target-LLM",
        max_concurrency: int = 1,
        request_delay: float = 0.0,
        trials: int = 1,
        adaptive_attacker: Optional[AdaptiveAttacker] = None,
        adaptive_max_turns: int = 0,
    ):
        self.target_adapter = target_adapter
        self.evaluators = evaluators
        self.target_name = target_name
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.request_delay = request_delay
        self.request_lock = asyncio.Lock()
        self.last_request_at = 0.0
        self.trials = max(1, int(trials))
        self.adaptive_attacker = adaptive_attacker
        self.adaptive_max_turns = max(0, int(adaptive_max_turns))

    async def _wait_for_request_slot(self) -> None:
        if self.request_delay <= 0:
            return
        async with self.request_lock:
            loop = asyncio.get_running_loop()
            wait = self.request_delay - (loop.time() - self.last_request_at)
            if wait > 0:
                await asyncio.sleep(wait)
            self.last_request_at = loop.time()

    async def _run_single_trial(self, probe: BaseProbe) -> ProbeSessionResult:
        defn = probe.get_definition()
        session = ProbeSession(defn)
        is_tool_probe = defn.owasp_category == OWASPCategory.LLM06_EXCESSIVE_AGENCY or bool(
            {"tool_misuse", "oob", "excessive_agency"} & set(defn.tags)
        )

        last_status: Optional[EvaluationStatus] = None
        next_turn_idx = 0

        for turn_idx in range(len(defn.turns)):
            turn_ctx = defn.turns[turn_idx].context_data
            prompt = probe.render_turn(turn_idx, context=turn_ctx)
            messages_to_send = session.message_history + [{"role": "user", "content": prompt}]

            await self._wait_for_request_slot()
            response = await self.target_adapter.send_prompt(
                messages_to_send,
                context_data=turn_ctx,
                enable_tools=is_tool_probe,
            )

            evaluations = [
                await evaluator.evaluate(defn, prompt, response)
                for evaluator in self.evaluators
            ]
            eval_result = (
                max(evaluations, key=lambda result: TURN_EVALUATOR_PRIORITY[result.status])
                if evaluations
                else None
            )

            session.add_turn(turn_idx, prompt, response, eval_result, evaluations)
            next_turn_idx = turn_idx + 1
            last_status = eval_result.status if eval_result else None

            if last_status in {EvaluationStatus.VULNERABLE, EvaluationStatus.ERROR}:
                break

        # Optional adaptive red-teaming follow-ups if static turns did not breach or error.
        if (
            self.adaptive_attacker is not None
            and self.adaptive_max_turns > 0
            and last_status not in {EvaluationStatus.VULNERABLE, EvaluationStatus.ERROR}
        ):
            for attempt in range(self.adaptive_max_turns):
                followup = await self.adaptive_attacker.generate_followup(
                    defn,
                    session.message_history,
                    attempt_index=attempt,
                )
                if not followup:
                    break

                messages_to_send = session.message_history + [{"role": "user", "content": followup}]
                await self._wait_for_request_slot()
                response = await self.target_adapter.send_prompt(
                    messages_to_send,
                    context_data={},
                    enable_tools=is_tool_probe,
                )
                evaluations = [
                    await evaluator.evaluate(defn, followup, response)
                    for evaluator in self.evaluators
                ]
                eval_result = (
                    max(evaluations, key=lambda result: TURN_EVALUATOR_PRIORITY[result.status])
                    if evaluations
                    else None
                )
                session.add_turn(next_turn_idx, followup, response, eval_result, evaluations)
                next_turn_idx += 1
                last_status = eval_result.status if eval_result else None
                if last_status in {EvaluationStatus.VULNERABLE, EvaluationStatus.ERROR}:
                    break

        return session.get_result()

    async def execute_probe(self, probe: BaseProbe) -> ProbeSessionResult:
        trial_results = [await self._run_single_trial(probe) for _ in range(self.trials)]
        if len(trial_results) == 1:
            single = trial_results[0]
            single.trial_count = 1
            single.vulnerable_trials = 1 if single.overall_vulnerable else 0
            single.attack_success_rate = 1.0 if single.overall_vulnerable else 0.0
            return single

        vulnerable_trials = sum(1 for r in trial_results if r.overall_vulnerable)
        best = max(trial_results, key=lambda r: SESSION_STATUS_PRIORITY[r.status])
        best.trial_count = len(trial_results)
        best.vulnerable_trials = vulnerable_trials
        best.attack_success_rate = round(vulnerable_trials / len(trial_results), 4)
        best.summary = (
            f"{best.summary} [ASR: {best.attack_success_rate * 100:.0f}% "
            f"({vulnerable_trials}/{len(trial_results)} trials)]"
        )
        return best

    def _build_report(self, session_results: List[ProbeSessionResult]) -> AssessmentReport:
        category_breakdown: Dict[str, int] = {}
        for result in session_results:
            cat = result.probe.owasp_category.value
            if result.overall_vulnerable:
                category_breakdown[cat] = category_breakdown.get(cat, 0) + 1

        vulnerabilities_found = sum(1 for r in session_results if r.status == EvaluationStatus.VULNERABLE)
        inconclusive_count = sum(1 for r in session_results if r.status == EvaluationStatus.INCONCLUSIVE)
        error_count = sum(1 for r in session_results if r.status == EvaluationStatus.ERROR)
        overall_asr = (
            round(
                sum(r.attack_success_rate for r in session_results) / len(session_results),
                4,
            )
            if session_results
            else 0.0
        )

        report = AssessmentReport(
            target_name=self.target_name,
            timestamp=datetime.now(timezone.utc).isoformat(),
            probes_executed=len(session_results),
            vulnerabilities_found=vulnerabilities_found,
            inconclusive_count=inconclusive_count,
            error_count=error_count,
            category_breakdown=category_breakdown,
            session_results=session_results,
            overall_asr=overall_asr,
        )
        posture_score, _ = compute_posture_score(report)
        report.posture_score = posture_score
        return report

    async def stream_assessment(
        self, probes: List[BaseProbe]
    ) -> AsyncIterator[Tuple[int, int, AssessmentReport]]:
        """Execute probes concurrently and yield `(completed, total, partial_report)` as each finishes."""
        total = len(probes)
        if total == 0:
            yield 0, 0, self._build_report([])
            return

        queue: asyncio.Queue[Tuple[int, ProbeSessionResult]] = asyncio.Queue()

        async def _worker(index: int, probe: BaseProbe) -> None:
            async with self.semaphore:
                res = await self.execute_probe(probe)
            await queue.put((index, res))

        tasks = [asyncio.create_task(_worker(idx, probe)) for idx, probe in enumerate(probes)]
        results_by_index: Dict[int, ProbeSessionResult] = {}
        try:
            for completed in range(1, total + 1):
                idx, res = await queue.get()
                results_by_index[idx] = res
                ordered = [results_by_index[i] for i in sorted(results_by_index)]
                yield completed, total, self._build_report(ordered)
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

    async def run_assessment(self, probes: List[BaseProbe]) -> AssessmentReport:
        final_report: Optional[AssessmentReport] = None
        async for _, _, report in self.stream_assessment(probes):
            final_report = report
        return final_report if final_report is not None else self._build_report([])
