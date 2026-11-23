from typing import List, Type
from llm_judge.probes.base import BaseProbe
from llm_judge.probes.direct_injection import (
    DirectInjectionSystemOverrideProbe,
    DirectInjectionRoleplayProbe,
)
from llm_judge.probes.encoding_obfuscation import (
    Base64ObfuscatedInjectionProbe,
    DelimiterRoleBoundaryProbe,
    MultiTurnGradualEscalationProbe,
    TaskHijackSummarizationProbe,
)
from llm_judge.probes.sensitive_disclosure import (
    SecretKeyDisclosureProbe,
    SystemPromptLeakageProbe,
    SystemPromptSummaryLeakageProbe,
)
from llm_judge.probes.indirect_injection import (
    IndirectPromptInjectionRAGProbe,
    PersistentMultiTurnRAGHijackProbe,
)
from llm_judge.probes.cross_tenant import CrossTenantDataLeakageProbe
from llm_judge.probes.output_handling import ImproperOutputHandlingXSSProbe
from llm_judge.probes.tool_poisoning import (
    ExcessiveAgencyToolExecutionProbe,
    ToolSSRFCallbackProbe,
)
from llm_judge.probes.unbounded_consumption import UnboundedConsumptionProbe
from llm_judge.probes.poisoning_misinfo import (
    FabricatedAuthoritySycophancyProbe,
    PoisonedContextBackdoorProbe,
    PoisonedFewShotBiasProbe,
    PrivilegeRoleElevationProbe,
)
from llm_judge.probes.custom_loader import (
    CustomProbeSpec,
    YAMLProbe,
    load_probes_from_yaml_file,
    load_probes_from_yaml_text,
)

ALL_PROBES: List[Type[BaseProbe]] = [
    DirectInjectionSystemOverrideProbe,
    DirectInjectionRoleplayProbe,
    Base64ObfuscatedInjectionProbe,
    MultiTurnGradualEscalationProbe,
    DelimiterRoleBoundaryProbe,
    TaskHijackSummarizationProbe,
    SystemPromptLeakageProbe,
    SystemPromptSummaryLeakageProbe,
    SecretKeyDisclosureProbe,
    IndirectPromptInjectionRAGProbe,
    PersistentMultiTurnRAGHijackProbe,
    CrossTenantDataLeakageProbe,
    ImproperOutputHandlingXSSProbe,
    ExcessiveAgencyToolExecutionProbe,
    ToolSSRFCallbackProbe,
    UnboundedConsumptionProbe,
    PoisonedContextBackdoorProbe,
    PoisonedFewShotBiasProbe,
    FabricatedAuthoritySycophancyProbe,
    PrivilegeRoleElevationProbe,
]


def get_all_probes() -> List[BaseProbe]:
    return [probe_cls() for probe_cls in ALL_PROBES]


__all__ = [
    "BaseProbe",
    "DirectInjectionSystemOverrideProbe",
    "DirectInjectionRoleplayProbe",
    "Base64ObfuscatedInjectionProbe",
    "MultiTurnGradualEscalationProbe",
    "DelimiterRoleBoundaryProbe",
    "TaskHijackSummarizationProbe",
    "SystemPromptLeakageProbe",
    "SystemPromptSummaryLeakageProbe",
    "SecretKeyDisclosureProbe",
    "IndirectPromptInjectionRAGProbe",
    "PersistentMultiTurnRAGHijackProbe",
    "CrossTenantDataLeakageProbe",
    "ImproperOutputHandlingXSSProbe",
    "ExcessiveAgencyToolExecutionProbe",
    "ToolSSRFCallbackProbe",
    "UnboundedConsumptionProbe",
    "PoisonedContextBackdoorProbe",
    "PoisonedFewShotBiasProbe",
    "FabricatedAuthoritySycophancyProbe",
    "PrivilegeRoleElevationProbe",
    "CustomProbeSpec",
    "YAMLProbe",
    "load_probes_from_yaml_file",
    "load_probes_from_yaml_text",
    "ALL_PROBES",
    "get_all_probes",
]
