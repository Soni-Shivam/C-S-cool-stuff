"""Google Gemini provider. `system` (trusted instructions) is passed as the model's
system_instruction; `user_data` (untrusted APK-derived evidence) is passed as content —
they are never concatenated, which is the primary prompt-injection defense (paper §4.4.6)."""
import json

from drishti.llm.provider import LLMProvider


class GeminiProvider(LLMProvider):
    name = "gemini"
    live = True

    def __init__(self, api_key: str, model: str):
        from google import genai

        self._genai = genai
        self._client = genai.Client(api_key=api_key)
        self.model = model

    def generate(self, system: str, user_data: str) -> str:
        from google.genai import types

        resp = self._client.models.generate_content(
            model=self.model,
            contents=user_data,
            config=types.GenerateContentConfig(system_instruction=system),
        )
        return resp.text or ""

    def generate_json(self, system: str, user_data: str, schema: dict) -> dict:
        from google.genai import types

        resp = self._client.models.generate_content(
            model=self.model,
            contents=user_data,
            config=types.GenerateContentConfig(
                system_instruction=system,
                response_mime_type="application/json",
                response_schema=schema,
            ),
        )
        return json.loads(resp.text)
