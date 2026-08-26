"""All cross-module types. Import-only, no logic.

docs/01_DATA_CONTRACTS.md is the source of truth for this package. If you need a
field that is not there, add it to the doc first, bump the contract version, then
implement — in that order. A model that exists only in code is a model the other
two tracks do not know about.

Contract version: 1.3.0 (additive containment admission contracts).
"""

from __future__ import annotations

from drishti.contracts.base import AnalyserResult, DrishtiModel
from drishti.contracts.containment import ContainmentChecks, ContainmentManifest
from drishti.contracts.corpus import (
    MALWARE_MIN_VT,
    TIME_BANDS,
    CorpusSample,
    Split,
)
from drishti.contracts.dynamic_trace import (
    ApiEvent,
    DecryptedBlob,
    DexLoadEvent,
    DynamicTrace,
    EvasionObservation,
    FailureRecord,
    FileWrite,
    HarnessMetadata,
    NetworkFlow,
    ObservationArtifact,
    ObservationEvent,
    SnapshotLifecycle,
    StrictWireModel,
    SyntheticC2Response,
    TraceSourceKind,
)
from drishti.contracts.evidence import (
    GROUNDING_REQUIRED,
    ChainVerification,
    EvidenceNode,
    EvidenceType,
)
from drishti.contracts.frontier import Morph, MorphKind, MorphPlan, SandboxPlan
from drishti.contracts.genai_verdict import (
    CodeInterpretation,
    GenAIVerdict,
    GroundedClaim,
    TechniqueMapping,
    ToolCallRecord,
    VerifiedString,
    VerifierStatus,
    VictimProfile,
    VisionMatch,
)
from drishti.contracts.job import PIPELINE_ORDER, Job, JobStage, StageEvent
from drishti.contracts.score import (
    BAND_FLOOR,
    BAND_ORDER,
    CompositeScore,
    FeatureAttribution,
    MLPrediction,
    ProposedAction,
    ScoreFactor,
    SeverityBand,
)
from drishti.contracts.static_report import (
    BenignLookalikeVerdict,
    CallPath,
    CertificateInfo,
    Component,
    ComponentKind,
    DecompiledMethod,
    FileMeta,
    Hypothesis,
    HypothesisKind,
    LookalikeAssessment,
    LookalikeSignal,
    PermissionCombo,
    Severity,
    StaticReport,
    ThreatIntel,
)

CONTRACT_VERSION = "1.3.0"

__all__ = [
    "BAND_FLOOR",
    "BAND_ORDER",
    "CONTRACT_VERSION",
    "GROUNDING_REQUIRED",
    "MALWARE_MIN_VT",
    "PIPELINE_ORDER",
    "TIME_BANDS",
    "AnalyserResult",
    "ApiEvent",
    "BenignLookalikeVerdict",
    "CallPath",
    "CertificateInfo",
    "ChainVerification",
    "CodeInterpretation",
    "Component",
    "ComponentKind",
    "CompositeScore",
    "ContainmentChecks",
    "ContainmentManifest",
    "CorpusSample",
    "DecompiledMethod",
    "DecryptedBlob",
    "DexLoadEvent",
    "DrishtiModel",
    "DynamicTrace",
    "EvasionObservation",
    "EvidenceNode",
    "EvidenceType",
    "FailureRecord",
    "FeatureAttribution",
    "FileMeta",
    "FileWrite",
    "GenAIVerdict",
    "GroundedClaim",
    "HarnessMetadata",
    "Hypothesis",
    "HypothesisKind",
    "Job",
    "JobStage",
    "LookalikeAssessment",
    "LookalikeSignal",
    "MLPrediction",
    "Morph",
    "MorphKind",
    "MorphPlan",
    "NetworkFlow",
    "ObservationArtifact",
    "ObservationEvent",
    "PermissionCombo",
    "ProposedAction",
    "SandboxPlan",
    "ScoreFactor",
    "Severity",
    "SeverityBand",
    "SnapshotLifecycle",
    "Split",
    "StageEvent",
    "StaticReport",
    "StrictWireModel",
    "SyntheticC2Response",
    "TechniqueMapping",
    "ThreatIntel",
    "ToolCallRecord",
    "TraceSourceKind",
    "VerifiedString",
    "VerifierStatus",
    "VictimProfile",
    "VisionMatch",
]
