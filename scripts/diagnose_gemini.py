"""Make one harmless Gemini request to diagnose the configured provider connection."""

import json
import os
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import httpx
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env", override=False)

from google import genai
from google.genai import errors, types

from services.gemini_service import (
    ANALYSIS_SCHEMA,
    AnalysisServiceError,
    SYSTEM_INSTRUCTIONS,
    _validate_result,
    get_configured_model,
)


def _provider_category(status: int, message: str) -> tuple[str, str]:
    lowered = message.lower()
    if status == 503 and any(
        term in lowered for term in ("high demand", "overload", "overloaded")
    ):
        return "provider_overloaded", "Google reports temporary model capacity pressure."
    if status == 503:
        return "provider_unavailable", "Google returned HTTP 503; the model service is unavailable."
    if status == 504 or "deadline" in lowered:
        return "provider_deadline", "Google did not complete the request before its deadline."
    if status == 429 and any(term in lowered for term in ("quota", "billing", "resource_exhausted")):
        return "quota_or_billing", "The API account may have reached a quota or billing limit."
    if status == 429:
        return "rate_limit", "The API account is temporarily rate limited."
    if status in {401, 403}:
        return "authentication_or_access", "Check the server key and its Gemini API access."
    if status in {400, 404}:
        return "invalid_request_or_model", "Check the configured model and request compatibility."
    if status >= 500:
        return "provider_error", "Google returned a temporary server-side error."
    return "provider_error", "Google rejected the diagnostic request."


def main() -> int:
    key = os.getenv("GEMINI_API_KEY", "").strip()
    model = get_configured_model()
    try:
        sdk_version = version("google-genai")
    except PackageNotFoundError:
        sdk_version = "unavailable"

    print(f"API key configured: {'yes' if key else 'no'}")
    print(f"Google GenAI SDK: {sdk_version}")
    print(f"Configured model: {model}")
    if not key:
        print("Result: not tested; set GEMINI_API_KEY in the project .env file.")
        return 2

    client = genai.Client(
        api_key=key,
        http_options=types.HttpOptions(
            timeout=20_000,
            retry_options=types.HttpRetryOptions(attempts=1),
        ),
    )
    try:
        response = client.models.generate_content(
            model=model,
            contents=(
                "This is a harmless integration check, not a real complaint. "
                "Return a minimal valid structured response stating that no incident facts were provided."
            ),
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTIONS,
                response_mime_type="application/json",
                response_schema=ANALYSIS_SCHEMA,
                max_output_tokens=1200,
            ),
        )
    except errors.APIError as exc:
        status = getattr(exc, "code", 0)
        if not isinstance(status, int):
            status = 0
        provider_message = str(getattr(exc, "message", "") or "")
        category, diagnostic = _provider_category(status, provider_message)
        print(f"Result: provider error (HTTP {status or 'unknown'})")
        print(f"Category: {category}")
        print(f"Diagnostic: {diagnostic}")
        return 1
    except (TimeoutError, httpx.TimeoutException):
        print("Result: request timed out")
        print("Category: client_timeout")
        print("Diagnostic: Google did not respond within the configured 20-second timeout.")
        return 1
    except httpx.RequestError as exc:
        print("Result: network error")
        print(f"Category: {type(exc).__name__}")
        print("Diagnostic: Check network access to the Google Generative Language API.")
        return 1
    finally:
        client.close()

    try:
        result = json.loads(response.text or "")
    except (TypeError, json.JSONDecodeError):
        print("Result: invalid model response")
        print("Category: malformed_response")
        print("Diagnostic: Gemini did not return the configured JSON response format.")
        return 1
    try:
        _validate_result(result)
    except (AnalysisServiceError, TypeError):
        print("Result: invalid model response")
        print("Category: malformed_response")
        print("Diagnostic: Gemini did not return a valid response matching the chatbot schema.")
        return 1
    print("Result: request succeeded")
    print("Category: success")
    print("Diagnostic: Gemini accepted the configured model and structured request.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
