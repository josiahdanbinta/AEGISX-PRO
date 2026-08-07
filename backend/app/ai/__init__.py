"""
AEGIS - AI Module
Provides LLM client, AI services, and intelligent automation.
"""
from app.ai.llm import llm_client, LLMClient
from app.ai.services import (
    AIService,
    IncidentAnalyzer,
    AlertAnalyzer,
    ThreatAnalyzer,
    RecommendationEngine,
    AIInvestigator,
    AICorrelationEngine,
)

__all__ = [
    "llm_client",
    "LLMClient",
    "AIService",
    "IncidentAnalyzer",
    "AlertAnalyzer",
    "ThreatAnalyzer",
    "RecommendationEngine",
    "AIInvestigator",
    "AICorrelationEngine",
]
