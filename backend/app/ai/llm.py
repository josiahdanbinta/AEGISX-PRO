"""
AEGIS - LLM Client Wrapper
Supports OpenAI, Azure OpenAI, and local models.
"""
import json
from typing import Any, Dict, List, Optional
import httpx
from app.core.config import settings


class LLMClient:
    """Unified LLM client for AI features."""

    def __init__(self):
        self.provider = settings.AI_PROVIDER
        self.model = settings.AI_MODEL
        self.api_key = settings.OPENAI_API_KEY
        self.base_url = settings.OPENAI_API_BASE or "https://api.openai.com/v1"
        self._enabled = settings.AI_ENABLED and (settings.OPENAI_API_KEY or settings.AZURE_OPENAI_KEY)
        # Azure configuration
        self.azure_key = settings.AZURE_OPENAI_KEY
        self.azure_endpoint = settings.AZURE_OPENAI_ENDPOINT
        self.azure_deployment = settings.AZURE_OPENAI_DEPLOYMENT

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _build_request(self, messages: List[Dict[str, str]], **kwargs) -> Dict:
        """Build the request payload based on provider."""
        if self.provider == "azure" and self.azure_endpoint and self.azure_deployment:
            return {
                "url": f"{self.azure_endpoint}/openai/deployments/{self.azure_deployment}/chat/completions?api-version=2024-02-15-preview",
                "headers": {"api-key": self.azure_key or "", "Content-Type": "application/json"},
                "json": {
                    "messages": messages,
                    "temperature": kwargs.get("temperature", settings.AI_TEMPERATURE),
                    "max_tokens": kwargs.get("max_tokens", settings.AI_MAX_TOKENS),
                },
            }
        return {
            "url": f"{self.base_url}/chat/completions",
            "headers": {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            "json": {
                "model": self.model or "gpt-4",
                "messages": messages,
                "temperature": kwargs.get("temperature", settings.AI_TEMPERATURE),
                "max_tokens": kwargs.get("max_tokens", settings.AI_MAX_TOKENS),
            },
        }

    async def complete(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Send completion request to LLM."""
        if not self._enabled:
            return json.dumps({"error": "AI is not enabled"})
        try:
            req = self._build_request(messages, **kwargs)
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(req["url"], headers=req["headers"], json=req["json"])
                if response.status_code == 200:
                    data = response.json()
                    return data["choices"][0]["message"]["content"]
                return json.dumps({"error": f"LLM error: {response.status_code}"})
        except Exception as e:
            return json.dumps({"error": str(e)})

    async def complete_structured(self, messages: List[Dict[str, str]], schema: Dict, **kwargs) -> Dict:
        """Get structured JSON response."""
        system_msg = messages[0]["content"] if messages else ""
        messages.insert(0, {"role": "system", "content": f"{system_msg}\n\nRespond ONLY with valid JSON matching this schema: {json.dumps(schema)}"})
        result = await self.complete(messages, **kwargs)
        try:
            return json.loads(result)
        except Exception:
            parsed = _extract_json(result)
            if parsed:
                return parsed
            return {"error": "Failed to parse AI response", "raw": result}


def _extract_json(text: str) -> Optional[Dict]:
    """Attempt to extract JSON object from a text response."""
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except Exception:
            pass
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except Exception:
            pass
    return None


llm_client = LLMClient()
