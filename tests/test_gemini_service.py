import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from google import genai
from google.genai import errors, types

from services import gemini_service


def valid_result(**changes):
    result = {
        "response_type": "final",
        "language": "English",
        "crime_type": "Other or uncertain",
        "confidence": 55,
        "severity": "Medium",
        "severity_explanation": "The reported account change is concerning, but no immediate financial loss was reported.",
        "summary": "A preliminary assessment based on the reported facts.",
        "facts": ["The account recovery email was changed."],
        "indicators": ["Unrecognized account change"],
        "missing_information": [],
        "follow_up_question": "",
        "evidence": ["Save account security alerts."],
        "next_steps": ["Use the service's official account recovery process."],
        "legal_topics": [],
    }
    result.update(changes)
    return result


class FakeModelRequest:
    def __init__(self, output_text=None, error=None, response=None):
        self.output_text = output_text
        self.error = error
        self.response = response
        self.request = None
        self.calls = 0

    def create(self, **kwargs):
        self.request = kwargs
        self.calls += 1
        if isinstance(self.error, list):
            error = self.error.pop(0)
        else:
            error = self.error
        if error:
            raise error
        if self.response is not None:
            return self.response
        return type("FakeResponse", (), {"text": self.output_text})()


class FakeClient:
    def __init__(self, output_text=None, error=None, response=None):
        self.models = type("FakeModelsApi", (), {})()
        self.models.generate_content = FakeModelRequest(output_text, error, response).create
        self.models.api = self.models.generate_content.__self__

    def close(self):
        pass


class GeminiServiceTests(unittest.TestCase):
    def run_analysis(self, message, result, conversation=None):
        client = FakeClient(json.dumps(result, ensure_ascii=False))
        response = gemini_service.analyze_complaint(message, conversation, client=client)
        return response, client.models.api.request

    def test_fake_social_media_account(self):
        result = valid_result(
            crime_type="Social media fraud",
            confidence=86,
            severity="Medium",
            summary="A fake social media profile appears to be impersonating the complainant.",
        )
        response, _ = self.run_analysis(
            "Someone created a fake Instagram profile using my name and photo.", result
        )
        self.assertEqual(response["crime_type"], "Social media fraud")

    def test_impersonation_call_followed_by_unauthorized_transaction(self):
        result = valid_result(
            crime_type="Financial cyber fraud",
            confidence=91,
            severity="High",
            facts=["A caller claimed to be customer support.", "An unauthorized transaction followed."],
        )
        response, _ = self.run_analysis(
            "Fake customer support asked me to install remote access software, then money was transferred.",
            result,
        )
        self.assertEqual(response["severity"], "High")
        self.assertEqual(len(response["facts"]), 2)

    def test_recovery_email_changed_without_permission(self):
        result = valid_result(crime_type="Account takeover", confidence=82)
        response, _ = self.run_analysis(
            "My account recovery email was changed without my permission.", result
        )
        self.assertEqual(response["crime_type"], "Account takeover")

    def test_ambiguous_incident_requires_follow_up(self):
        result = valid_result(
            response_type="follow_up",
            crime_type="Other or uncertain",
            confidence=20,
            missing_information=["Whether money or account access was affected."],
            follow_up_question="Did you lose access to an account or money?",
        )
        response, _ = self.run_analysis("Something strange happened online.", result)
        self.assertEqual(response["response_type"], "follow_up")
        self.assertEqual(response["follow_up_question"], "Did you lose access to an account or money?")

    def test_tamil_complaint_is_preserved_for_model(self):
        response, request = self.run_analysis(
            "என் வங்கி கணக்கில் அனுமதியின்றி பணம் எடுத்துள்ளனர்.",
            valid_result(language="Tamil", crime_type="Financial cyber fraud"),
        )
        self.assertEqual(response["language"], "Tamil")
        self.assertIn("என் வங்கி", request["contents"])

    def test_hindi_complaint_is_preserved_for_model(self):
        response, request = self.run_analysis(
            "मेरे बैंक खाते से बिना अनुमति पैसे निकाल लिए गए।",
            valid_result(language="Hindi", crime_type="Financial cyber fraud"),
        )
        self.assertEqual(response["language"], "Hindi")
        self.assertIn("मेरे बैंक", request["contents"])

    def test_roman_tamil_complaint_is_preserved_for_model(self):
        response, request = self.run_analysis(
            "En account la irundhu money transfer aayiduchu, naan pannala.",
            valid_result(language="Roman Tamil", crime_type="Financial cyber fraud"),
        )
        self.assertEqual(response["language"], "Roman Tamil")
        self.assertIn("En account", request["contents"])

    def test_yes_follow_up_includes_prior_context(self):
        conversation = [
            {"role": "user", "content": "I got a suspicious bank call."},
            {"role": "assistant", "content": "Was there an unauthorized transaction?"},
        ]
        result = valid_result(crime_type="Financial cyber fraud", confidence=88)
        _, request = self.run_analysis("Yes", result, conversation)
        self.assertTrue(request["contents"].endswith("User: Yes"))
        self.assertIn("User: I got a suspicious bank call.", request["contents"])
        self.assertIn("Assistant: Was there an unauthorized transaction?", request["contents"])

    def test_missing_api_key_is_a_configuration_error(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
            with self.assertRaises(gemini_service.AnalysisConfigurationError):
                gemini_service.analyze_complaint("A report", client=None)

    def test_client_uses_bounded_timeout_without_sdk_managed_retries(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
            with patch.object(gemini_service.genai, "Client") as create_client:
                gemini_service._get_client()
        http_options = create_client.call_args.kwargs["http_options"]
        self.assertEqual(http_options.timeout, 20_000)
        self.assertEqual(http_options.retry_options.attempts, 1)

    def test_invalid_api_key_is_a_configuration_error(self):
        client = FakeClient(error=errors.APIError(401, {"message": "Invalid API key"}))
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
            with patch.object(gemini_service.genai, "Client", return_value=client):
                with self.assertRaises(gemini_service.AnalysisConfigurationError):
                    gemini_service.analyze_complaint("A report")

    def test_timeout_does_not_return_a_success_assessment(self):
        client = FakeClient(error=TimeoutError())
        with self.assertRaises(gemini_service.AnalysisServiceError) as raised:
            gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(raised.exception.failure_kind, "timeout")

    def test_http_timeout_does_not_return_a_success_assessment(self):
        client = FakeClient(error=httpx.ReadTimeout("request timed out"))
        with self.assertRaises(gemini_service.AnalysisServiceError) as raised:
            gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(raised.exception.failure_kind, "timeout")

    def test_network_error_does_not_return_a_success_assessment(self):
        client = FakeClient(error=httpx.ConnectError("connection failed"))
        with self.assertRaises(gemini_service.AnalysisServiceError) as raised:
            gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(raised.exception.failure_kind, "provider_unavailable")

    @staticmethod
    def api_error(status, message, headers=None):
        response = httpx.Response(
            status,
            request=httpx.Request("POST", "https://generativelanguage.googleapis.com/"),
            headers=headers or {},
        )
        return errors.APIError(
            status,
            {"message": message, "status": "RESOURCE_EXHAUSTED" if status == 429 else "UNAVAILABLE"},
            response=response,
        )

    def test_temporary_rate_limit_retries_with_bounded_retry_after(self):
        temporary_error = self.api_error(
            429,
            "Request rate limit exceeded.",
            {"retry-after": "1"},
        )
        client = FakeClient(json.dumps(valid_result()), error=[temporary_error, None])
        with patch.object(gemini_service.time, "sleep") as sleep:
            result = gemini_service.analyze_complaint("A report", client=client)

        self.assertEqual(result["response_type"], "final")
        self.assertEqual(client.models.api.calls, 2)
        self.assertGreaterEqual(sleep.call_args.args[0], 1.0)

    def test_rate_limit_uses_retry_delay_from_api_error_details(self):
        response = httpx.Response(
            429,
            request=httpx.Request("POST", "https://generativelanguage.googleapis.com/"),
            json={
                "error": {
                    "message": "Resource exhausted.",
                    "status": "RESOURCE_EXHAUSTED",
                    "details": [
                        {
                            "@type": "type.googleapis.com/google.rpc.RetryInfo",
                            "retryDelay": "1.25s",
                        }
                    ],
                }
            },
        )
        error = errors.APIError(
            429,
            {"message": "Resource exhausted.", "status": "RESOURCE_EXHAUSTED"},
            response=response,
        )
        client = FakeClient(json.dumps(valid_result()), error=[error, None])
        with patch.object(gemini_service.time, "sleep") as sleep:
            result = gemini_service.analyze_complaint("A report", client=client)

        self.assertEqual(result["response_type"], "final")
        self.assertEqual(client.models.api.calls, 2)
        self.assertGreaterEqual(sleep.call_args.args[0], 1.25)

    def test_resource_exhausted_rate_limit_retries_once_when_delay_is_short(self):
        error = self.api_error(
            429,
            "Requests are temporarily limited.",
            {"retry-after": "0.5"},
        )
        client = FakeClient(json.dumps(valid_result()), error=[error, None])
        with patch.object(gemini_service.time, "sleep"):
            result = gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(result["response_type"], "final")
        self.assertEqual(client.models.api.calls, 2)

    def test_resource_exhausted_without_retry_delay_is_not_retried(self):
        error = self.api_error(429, "Resource exhausted.")
        client = FakeClient(error=[error, None])
        with patch.object(gemini_service.time, "sleep") as sleep:
            with self.assertRaises(gemini_service.AnalysisServiceError) as raised:
                gemini_service.analyze_complaint("A report", client=client)

        self.assertEqual(raised.exception.failure_kind, "rate_limit")
        self.assertEqual(client.models.api.calls, 1)
        sleep.assert_not_called()

    def test_daily_quota_error_is_not_retried_even_with_retry_delay(self):
        error = self.api_error(
            429,
            "Daily quota exceeded. Try again later.",
            {"retry-after": "1"},
        )
        client = FakeClient(error=[error, None])
        with patch.object(gemini_service.time, "sleep") as sleep:
            with self.assertRaises(gemini_service.AnalysisServiceError) as raised:
                gemini_service.analyze_complaint("A report", client=client)

        self.assertEqual(raised.exception.failure_kind, "billing_limit")
        self.assertEqual(client.models.api.calls, 1)
        sleep.assert_not_called()

    def test_daily_quota_metadata_is_not_retried(self):
        response = httpx.Response(
            429,
            request=httpx.Request("POST", "https://generativelanguage.googleapis.com/"),
            json={
                "error": {
                    "message": "Resource exhausted.",
                    "status": "RESOURCE_EXHAUSTED",
                    "details": [
                        {"quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier"},
                        {
                            "@type": "type.googleapis.com/google.rpc.RetryInfo",
                            "retryDelay": "1s",
                        },
                    ],
                }
            },
        )
        error = errors.APIError(
            429,
            {"message": "Resource exhausted.", "status": "RESOURCE_EXHAUSTED"},
            response=response,
        )
        client = FakeClient(error=[error, None])
        with patch.object(gemini_service.time, "sleep") as sleep:
            with self.assertRaises(gemini_service.AnalysisServiceError) as raised:
                gemini_service.analyze_complaint("A report", client=client)

        self.assertEqual(raised.exception.failure_kind, "billing_limit")
        self.assertEqual(client.models.api.calls, 1)
        sleep.assert_not_called()

    def test_temporary_503_retries_then_succeeds(self):
        client = FakeClient(
            json.dumps(valid_result()),
            error=[self.api_error(503, "Service unavailable."), None],
        )
        with patch.object(gemini_service.time, "sleep"):
            result = gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(result["response_type"], "final")
        self.assertEqual(client.models.api.calls, 2)

    def test_high_demand_503_is_classified_as_provider_overload(self):
        error = self.api_error(
            503,
            "This model is currently experiencing high demand. Please try again later.",
        )
        client = FakeClient(error=[error, error, error])
        with patch.object(gemini_service.time, "sleep"):
            with self.assertRaises(gemini_service.AnalysisServiceError) as raised:
                gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(raised.exception.failure_kind, "provider_overloaded")
        self.assertEqual(raised.exception.code, "503")
        self.assertIn("high demand", str(raised.exception))
        self.assertEqual(client.models.api.calls, 3)

    def test_504_deadline_is_not_misclassified_as_high_demand(self):
        error = self.api_error(504, "Deadline expired before operation could complete.")
        client = FakeClient(error=[error, error, error])
        with patch.object(gemini_service.time, "sleep"):
            with self.assertRaises(gemini_service.AnalysisServiceError) as raised:
                gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(raised.exception.failure_kind, "provider_deadline")
        self.assertIn("provider deadline", str(raised.exception))
        self.assertNotIn("high demand", str(raised.exception))
        self.assertEqual(client.models.api.calls, 3)

    def test_transient_gateway_and_server_errors_are_retried(self):
        for status in (500, 502, 504):
            with self.subTest(status=status):
                client = FakeClient(
                    json.dumps(valid_result()),
                    error=[self.api_error(status, "Temporary service failure."), None],
                )
                with patch.object(gemini_service.time, "sleep"):
                    gemini_service.analyze_complaint("A report", client=client)
                self.assertEqual(client.models.api.calls, 2)

    def test_repeated_503_exhausts_bounded_retries(self):
        error = self.api_error(503, "Service unavailable.")
        client = FakeClient(error=[error, error, error])
        with patch.object(gemini_service.time, "sleep") as sleep:
            with self.assertRaisesRegex(
                gemini_service.AnalysisServiceError,
                "HTTP 503",
            ) as raised:
                gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(raised.exception.failure_kind, "provider_unavailable")
        self.assertEqual(client.models.api.calls, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_quota_limit_is_not_retried_and_has_billing_guidance(self):
        quota_error = self.api_error(
            429,
            "You have exceeded your billing quota.",
        )
        client = FakeClient(error=[quota_error, None])
        with patch.object(gemini_service.time, "sleep") as sleep:
            with self.assertRaisesRegex(
                gemini_service.AnalysisServiceError,
                "quota or billing limit",
            ):
                gemini_service.analyze_complaint("A report", client=client)

        self.assertEqual(client.models.api.calls, 1)
        sleep.assert_not_called()

    def test_quota_permission_error_is_not_misreported_as_invalid_api_key(self):
        client = FakeClient(error=self.api_error(403, "The project quota has been exceeded."))
        with self.assertRaisesRegex(gemini_service.AnalysisServiceError, "quota or billing limit"):
            gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(client.models.api.calls, 1)

    def test_forbidden_project_access_has_accurate_permission_category(self):
        client = FakeClient(error=self.api_error(403, "The caller lacks project permissions."))
        with self.assertRaises(gemini_service.AnalysisConfigurationError) as raised:
            gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(raised.exception.failure_kind, "permission_denied")
        self.assertEqual(client.models.api.calls, 1)

    def test_bad_request_is_reported_as_configuration_error_without_retry(self):
        client = FakeClient(error=self.api_error(400, "Invalid generation configuration."))
        with self.assertRaises(gemini_service.AnalysisConfigurationError) as raised:
            gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(raised.exception.failure_kind, "invalid_request")
        self.assertEqual(client.models.api.calls, 1)

    def test_provider_error_logging_does_not_include_provider_message_or_secrets(self):
        error = self.api_error(
            429,
            "Request limited for API key: token-secret-value",
        )
        client = FakeClient(error=error)
        with patch.object(gemini_service.time, "sleep"):
            with self.assertLogs(gemini_service.logger, level="WARNING") as logs:
                with self.assertRaises(gemini_service.AnalysisServiceError):
                    gemini_service.analyze_complaint("A report", client=client)

        output = "\n".join(logs.output)
        self.assertIn("status=429", output)
        self.assertIn("Request limited", output)
        self.assertIn("api_error_code=RESOURCE_EXHAUSTED", output)
        self.assertNotIn("token-secret-value", output)

    def test_provider_error_logging_redacts_complaint_and_personal_data(self):
        complaint = "Jane Doe reported a transfer from jane@example.test at 555-010-1234"
        error = self.api_error(503, f"Request failed for complaint: {complaint}.")
        client = FakeClient(error=error)
        with patch.object(gemini_service.time, "sleep"):
            with self.assertLogs(gemini_service.logger, level="WARNING") as logs:
                with self.assertRaises(gemini_service.AnalysisServiceError):
                    gemini_service.analyze_complaint(complaint, client=client)
        output = "\n".join(logs.output)
        self.assertNotIn("Jane Doe", output)
        self.assertNotIn("jane@example.test", output)
        self.assertNotIn("555-010-1234", output)

    def test_malformed_model_output_is_rejected(self):
        client = FakeClient(output_text="{not valid JSON")
        with self.assertRaises(gemini_service.AnalysisServiceError):
            gemini_service.analyze_complaint("A report", client=client)

    def test_markdown_fenced_json_is_parsed(self):
        client = FakeClient(output_text=f"```json\n{json.dumps(valid_result())}\n```")
        result = gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(result["response_type"], "final")

    def test_sdk_parsed_response_is_used_when_text_is_not_available(self):
        response = SimpleNamespace(
            parsed=valid_result(),
            candidates=[
                SimpleNamespace(
                    content=SimpleNamespace(parts=[]),
                    finish_reason=types.FinishReason.STOP,
                )
            ],
            prompt_feedback=None,
            model_version="gemini-test",
        )
        client = FakeClient(response=response)
        result = gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(result["crime_type"], "Other or uncertain")

    def test_empty_model_response_is_diagnosed(self):
        client = FakeClient(output_text="")
        with self.assertRaises(gemini_service.AnalysisServiceError) as raised:
            gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(raised.exception.failure_kind, "invalid_response")
        self.assertEqual(raised.exception.diagnostic, "response contained no candidates or parsed output")

    def test_safety_block_does_not_create_an_assessment(self):
        response = types.GenerateContentResponse(
            candidates=[
                types.Candidate(
                    content=types.Content(parts=[], role="model"),
                    finish_reason=types.FinishReason.SAFETY,
                )
            ],
            prompt_feedback=types.GenerateContentResponsePromptFeedback(
                block_reason="SAFETY"
            ),
        )
        client = FakeClient(response=response)
        with self.assertRaises(gemini_service.AnalysisServiceError) as raised:
            gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(raised.exception.failure_kind, "safety_blocked")
        self.assertIn("safety policy", str(raised.exception))

    def test_max_tokens_is_diagnosed_as_incomplete_not_invalid_json(self):
        response = types.GenerateContentResponse(
            candidates=[
                types.Candidate(
                    content=types.Content(parts=[], role="model"),
                    finish_reason=types.FinishReason.MAX_TOKENS,
                )
            ]
        )
        client = FakeClient(response=response)
        with self.assertRaises(gemini_service.AnalysisServiceError) as raised:
            gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(raised.exception.failure_kind, "incomplete_response")

    def test_missing_fields_are_logged_by_name_without_logging_output(self):
        incomplete = valid_result()
        del incomplete["severity_explanation"]
        client = FakeClient(output_text=json.dumps(incomplete))
        with self.assertLogs(gemini_service.logger, level="WARNING") as logs:
            with self.assertRaises(gemini_service.AnalysisServiceError):
                gemini_service.analyze_complaint("A report", client=client)
        output = "\n".join(logs.output)
        self.assertIn("severity_explanation", output)
        self.assertNotIn("A report", output)

    def test_incomplete_model_output_is_rejected(self):
        result = valid_result()
        del result["severity_explanation"]
        client = FakeClient(output_text=json.dumps(result))
        with self.assertRaises(gemini_service.AnalysisServiceError) as raised:
            gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(raised.exception.failure_kind, "invalid_response")

    def test_unrecognized_output_fields_do_not_invalidate_a_complete_assessment(self):
        result = valid_result()
        result["extra_field"] = "untrusted extra"
        client = FakeClient(output_text=json.dumps(result))
        assessment = gemini_service.analyze_complaint("A report", client=client)
        self.assertNotIn("extra_field", assessment)
        self.assertEqual(assessment["response_type"], "final")

    def test_final_assessment_ignores_redundant_follow_up_question(self):
        response = SimpleNamespace(
            parsed=valid_result(
                follow_up_question="Do you have any other information to add?"
            ),
            candidates=[
                SimpleNamespace(
                    content=SimpleNamespace(parts=[]),
                    finish_reason=types.FinishReason.STOP,
                )
            ],
            prompt_feedback=None,
            model_version="gemini-test",
        )
        client = FakeClient(response=response)

        assessment = gemini_service.analyze_complaint("A report", client=client)

        self.assertEqual(assessment["response_type"], "final")
        self.assertEqual(assessment["follow_up_question"], "")
        self.assertEqual(assessment["crime_type"], "Other or uncertain")

    def test_invalid_model_is_configuration_error_without_retry(self):
        client = FakeClient(error=self.api_error(404, "Model models/not-real is not found."))
        with patch.dict(os.environ, {"GEMINI_MODEL": "models/not-real"}):
            with self.assertRaisesRegex(
                gemini_service.AnalysisConfigurationError,
                "GEMINI_MODEL",
            ) as raised:
                gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(raised.exception.failure_kind, "invalid_model")
        self.assertEqual(client.models.api.calls, 1)

    def test_retry_after_beyond_wait_budget_does_not_retry_early(self):
        client = FakeClient(
            error=[self.api_error(503, "Service unavailable.", {"retry-after": "30"})]
        )
        with patch.object(gemini_service.time, "sleep") as sleep:
            with self.assertRaises(gemini_service.AnalysisServiceError) as raised:
                gemini_service.analyze_complaint("A report", client=client)
        self.assertEqual(client.models.api.calls, 1)
        self.assertIn("30 seconds", str(raised.exception))
        self.assertEqual(raised.exception.retry_after_seconds, 30)
        sleep.assert_not_called()

    def test_inconsistent_follow_up_payload_is_rejected(self):
        result = valid_result(response_type="follow_up", follow_up_question="")
        client = FakeClient(output_text=json.dumps(result))
        with self.assertRaises(gemini_service.AnalysisServiceError):
            gemini_service.analyze_complaint("A report", client=client)

    def test_gemini_generate_content_uses_json_schema(self):
        result, request = self.run_analysis("A complaint", valid_result())
        self.assertEqual(result["crime_type"], "Other or uncertain")
        self.assertEqual(request["model"], "gemini-3.1-flash-lite")
        self.assertEqual(request["config"].response_mime_type, "application/json")
        self.assertEqual(request["config"].response_schema, gemini_service.ANALYSIS_SCHEMA)
        self.assertEqual(request["config"].max_output_tokens, 2048)
        self.assertEqual(
            request["config"].thinking_config.thinking_level,
            types.ThinkingLevel.MINIMAL,
        )
        self.assertEqual(request["config"].system_instruction, gemini_service.SYSTEM_INSTRUCTIONS)

    def test_official_sdk_serializes_gemini_request_with_mock_transport(self):
        output_text = json.dumps(valid_result())
        request_body = {}

        def respond(request):
            request_body.update(json.loads(request.content))
            return httpx.Response(
                200,
                json={
                    "candidates": [
                        {
                            "content": {
                                "parts": [{"text": output_text}],
                                "role": "model",
                            },
                            "finishReason": "STOP",
                            "index": 0,
                        }
                    ],
                    "modelVersion": "gemini-3.8-flash",
                },
            )

        http_client = httpx.Client(transport=httpx.MockTransport(respond))
        client = genai.Client(
            api_key="test-key",
            http_options=types.HttpOptions(httpx_client=http_client),
        )
        try:
            result = gemini_service.analyze_complaint("A complaint", client=client)
        finally:
            client.close()

        self.assertEqual(result["crime_type"], "Other or uncertain")
        self.assertEqual(request_body["generationConfig"]["responseMimeType"], "application/json")
        self.assertEqual(
            request_body["generationConfig"]["responseSchema"]["properties"]["crime_type"]["enum"],
            gemini_service.CRIME_CATEGORIES,
        )
        self.assertEqual(
            request_body["systemInstruction"]["parts"][0]["text"],
            gemini_service.SYSTEM_INSTRUCTIONS,
        )
        self.assertEqual(
            request_body["generationConfig"]["thinkingConfig"]["thinking_level"],
            "MINIMAL",
        )
        self.assertEqual(request_body["generationConfig"]["maxOutputTokens"], 2048)


if __name__ == "__main__":
    unittest.main()
