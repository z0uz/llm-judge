from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class OWASPCategory(str, Enum):
    LLM01_PROMPT_INJECTION = "LLM01: Direct & Indirect Prompt Injection"
    LLM02_SENSITIVE_INFO_DISCLOSURE = "LLM02: Sensitive Information Disclosure"
    LLM03_SUPPLY_CHAIN = "LLM03: Supply Chain Vulnerabilities"
    LLM04_DATA_SYSTEM_POISONING = "LLM04: Data and Model Poisoning"
    LLM05_IMPROPER_OUTPUT_HANDLING = "LLM05: Improper Output Handling"
    LLM06_EXCESSIVE_AGENCY = "LLM06: Excessive Agency & Tool Misuse"
    LLM07_SYSTEM_PROMPT_LEAKAGE = "LLM07: System Prompt Leakage"
    LLM08_VECTOR_RAG_WEAKNESSES = "LLM08: Vector and RAG Weaknesses"
    LLM09_MISCONFIGURATION = "LLM09: Misconfiguration & Access Control"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10: Unbounded Consumption"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EvaluationStatus(str, Enum):
    VULNERABLE = "VULNERABLE"
    SECURE = "SECURE"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class ProbeTurn(BaseModel):
    user_prompt: str
    context_data: Dict[str, Any] = Field(default_factory=dict)


class ProbeDefinition(BaseModel):
    id: str
    name: str
    description: str
    owasp_category: OWASPCategory
    severity: Severity
    turns: List[ProbeTurn]
    tags: List[str] = Field(default_factory=list)
    canary_string: Optional[str] = None


class TargetRequest(BaseModel):
    messages: List[Dict[str, str]]
    parameters: Dict[str, Any] = Field(default_factory=dict)


class TargetResponse(BaseModel):
    raw_content: str
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class EvaluationResult(BaseModel):
    probe_id: str
    status: EvaluationStatus
    vulnerable: bool
    score: float = Field(ge=0.0, le=1.0, description="0.0 secure, 1.0 fully compromised")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evaluator_name: str
    evidence: str
    owasp_category: OWASPCategory
    severity: Severity


class SessionTurn(BaseModel):
    turn_index: int
    prompt_sent: str
    target_response: TargetResponse
    evaluation: Optional[EvaluationResult] = None
    evaluations: List[EvaluationResult] = Field(default_factory=list)


class ProbeSessionResult(BaseModel):
    probe: ProbeDefinition
    turns: List[SessionTurn]
    status: EvaluationStatus
    overall_vulnerable: bool
    max_severity: Severity
    summary: str
    trial_count: int = 1
    vulnerable_trials: int = 0
    attack_success_rate: float = 0.0


class AssessmentReport(BaseModel):
    schema_version: str = "1.1"
    target_name: str
    timestamp: str
    probes_executed: int
    vulnerabilities_found: int
    inconclusive_count: int = 0
    error_count: int = 0
    category_breakdown: Dict[str, int]
    session_results: List[ProbeSessionResult]
    posture_score: Optional[int] = None
    overall_asr: float = 0.0
