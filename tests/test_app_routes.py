import os
import tempfile
import unittest
from unittest.mock import patch

os.environ["DB_TYPE"] = "sqlite"
_bootstrap_dir = tempfile.TemporaryDirectory()
os.environ["CYBERLEGAL_DB_PATH"] = os.path.join(_bootstrap_dir.name, "bootstrap.db")

import app as cyberlegal_app
_bootstrap_dir.cleanup()


class ChatRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cyberlegal_app.app.config.update(
            TESTING=True,
            DATABASE=os.path.join(cls.temp_dir.name, "test.db"),
        )
        cyberlegal_app.initialize_database()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        connection, _ = cyberlegal_app.get_db_connection()
        try:
            connection.execute("DELETE FROM chat_messages")
            connection.execute("DELETE FROM chat_sessions")
            connection.execute("DELETE FROM reports")
            connection.commit()
        finally:
            connection.close()
        self.client = cyberlegal_app.app.test_client()
        with self.client.session_transaction() as user_session:
            user_session["logged_in"] = True
            user_session["user_id"] = 10
            user_session["username"] = "test-user"

    def test_health_reports_safe_effective_gemini_runtime_configuration(self):
        with patch.dict(
            os.environ,
            {"GEMINI_API_KEY": "test-key", "GEMINI_MODEL": "gemini-test-model"},
        ):
            response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["ai_configured"])
        self.assertEqual(data["gemini_model"], "gemini-test-model")
        self.assertTrue(data["google_genai_version"])
        self.assertNotIn("GEMINI_API_KEY", data)

    @staticmethod
    def analysis(**changes):
        result = {
            "response_type": "final",
            "language": "English",
            "crime_type": "Financial cyber fraud",
            "confidence": 88,
            "severity": "High",
            "severity_explanation": "An unauthorized transfer may require urgent bank contact.",
            "summary": "An unauthorized transfer was reported.",
            "facts": ["An unauthorized transfer was reported."],
            "indicators": ["Unauthorized transaction"],
            "missing_information": [],
            "follow_up_question": "",
            "evidence": ["Preserve the bank transaction alert."],
            "next_steps": ["Contact the bank immediately."],
            "legal_topics": [],
        }
        result.update(changes)
        return result

    def test_chat_endpoint_persists_contextual_follow_up(self):
        first = self.analysis(
            response_type="follow_up",
            follow_up_question="Did an unauthorized transaction occur?",
        )
        second = self.analysis()
        with patch.object(cyberlegal_app, "analyze_complaint", side_effect=[first, second]) as analyzer:
            response = self.client.post(
                "/api/chat",
                json={"message": "I received a suspicious support call.", "session_id": "followup-session"},
            )
            self.assertEqual(response.status_code, 200)
            follow_up = response.get_json()
            self.assertEqual(follow_up["type"], "follow_up")
            self.assertIn("AI estimate", follow_up["confidence_label"])
            self.assertTrue(follow_up["legal_guidance"]["verification_needed"])
            self.assertEqual(follow_up["legal_guidance"]["verified_references"], [])

            response = self.client.post(
                "/api/chat",
                json={"message": "Yes", "session_id": "followup-session"},
            )
            self.assertEqual(response.status_code, 200)
            final = response.get_json()
            self.assertEqual(final["type"], "final")
            self.assertEqual(final["crime_type"], "Financial cyber fraud")
            self.assertEqual(final["severity"], "High")
            self.assertEqual(final["severity_explanation"], "An unauthorized transfer may require urgent bank contact.")
            self.assertEqual(final["evidence_to_preserve"], ["Preserve the bank transaction alert."])
            self.assertIn("Contact the bank immediately.", final["recommended_actions"])
            self.assertIn("preliminary AI assessment", final["disclaimer"])
            context = analyzer.call_args_list[1].args[1]
            self.assertEqual(context[-1]["content"], "Did an unauthorized transaction occur?")

        history = self.client.get("/api/chat-history/followup-session")
        self.assertEqual(history.status_code, 200)
        self.assertEqual(len(history.get_json()["messages"]), 4)
        saved = self.client.post(
            "/api/reports",
            json={
                "session_id": "followup-session",
                "category": "Forged category",
                "confidence": 1,
                "legal_guidance": {"applicable_laws": [{"section": "999"}]},
                "answers": {"forged question": "forged answer"},
            },
        )
        self.assertEqual(saved.status_code, 201)
        report = self.client.get(f"/api/reports/{saved.get_json()['report_id']}").get_json()
        self.assertEqual(report["detected_category"], "Financial Cyber Fraud")
        self.assertEqual(report["confidence"], 88)
        self.assertEqual(
            report["follow_up_answers"]["Did an unauthorized transaction occur?"],
            "Yes",
        )
        self.assertEqual(report["legal_guidance"]["legal_provisions"], [])
        self.assertEqual(
            report["assessment"]["summary"],
            "An unauthorized transfer was reported.",
        )

    def test_existing_dashboard_and_incident_routes_remain_available(self):
        self.assertEqual(self.client.get("/").status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/incident-report").status_code, 200)
        self.assertEqual(self.client.get("/static/css/style.css").status_code, 200)
        self.assertEqual(self.client.get("/static/js/app.js").status_code, 200)

    def test_empty_or_whitespace_session_id_creates_a_new_session(self):
        for session_id in ("", "   "):
            with self.subTest(session_id=repr(session_id)):
                with patch.object(cyberlegal_app, "analyze_complaint", return_value=self.analysis()):
                    response = self.client.post(
                        "/api/chat",
                        json={"message": "A complaint", "session_id": session_id},
                    )
                self.assertEqual(response.status_code, 200)
                generated_id = response.get_json()["session_id"]
                self.assertTrue(generated_id)
                self.assertNotEqual(generated_id, session_id)
                self.assertEqual(
                    cyberlegal_app.get_chat_session_owner(generated_id),
                    10,
                )

    def test_chat_rejects_another_users_session(self):
        cyberlegal_app.create_chat_session(
            "owned-by-another-user", "A complaint", "English", user_id=999
        )
        with patch.object(cyberlegal_app, "analyze_complaint") as analyzer:
            response = self.client.post(
                "/api/chat",
                json={"message": "Another complaint", "session_id": "owned-by-another-user"},
            )
        self.assertEqual(response.status_code, 404)
        analyzer.assert_not_called()

    def test_report_details_are_scoped_to_signed_in_user(self):
        report_id = cyberlegal_app.save_report(
            {
                "complaint": "A private complaint",
                "category": "Financial Cyber Fraud",
                "user_id": 999,
            }
        )
        response = self.client.get(f"/api/reports/{report_id}")
        self.assertEqual(response.status_code, 404)

    def test_saved_legacy_or_submitted_legal_citations_are_not_returned(self):
        report_id = cyberlegal_app.save_report(
            {
                "complaint": "A private complaint",
                "category": "Financial Cyber Fraud",
                "user_id": 10,
                "legal_guidance": {
                    "applicable_laws": [{"act": "Unknown Act", "section": "999"}],
                    "legal_provisions": [{"act": "Unknown Act", "section": "998"}],
                },
            }
        )
        response = self.client.get(f"/api/reports/{report_id}")
        guidance = response.get_json()["legal_guidance"]
        self.assertEqual(guidance["applicable_laws"], [])
        self.assertEqual(guidance["legal_provisions"], [])
        self.assertNotIn("999", str(guidance))

    def test_legal_guidance_page_has_no_unverified_section_mappings(self):
        categories = cyberlegal_app.build_legal_guidance_categories()
        self.assertTrue(all(category["provisions"] == [] for category in categories))

    def test_chat_without_login_is_rejected(self):
        self.client.get("/logout")
        response = self.client.post("/api/chat", json={"message": "A complaint"})
        self.assertEqual(response.status_code, 401)

    def test_retry_and_chat_history_routes_require_authentication(self):
        self.client.get("/logout")
        retry = self.client.post("/api/chat/retry", json={"session_id": "private"})
        history = self.client.get("/api/chat-history")
        detail = self.client.get("/api/chat-history/private")
        self.assertEqual(retry.status_code, 401)
        self.assertEqual(history.status_code, 401)
        self.assertEqual(detail.status_code, 401)

    def test_chat_does_not_forward_authentication_secrets(self):
        with patch.object(cyberlegal_app, "analyze_complaint") as analyzer:
            response = self.client.post(
                "/api/chat",
                json={"message": "The OTP is 123456"},
            )
        self.assertEqual(response.status_code, 400)
        analyzer.assert_not_called()

    def test_missing_api_key_is_not_reported_as_a_successful_assessment(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
            response = self.client.post(
                "/api/chat",
                json={"message": "My password was compromised yesterday."},
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["type"], "error")
        self.assertIn("not configured", response.get_json()["response"])

    def test_invalid_model_response_is_saved_failed_and_marked_retryable(self):
        with patch.object(
            cyberlegal_app,
            "analyze_complaint",
            side_effect=cyberlegal_app.AnalysisServiceError(
                "Gemini returned an unreadable response. Your complaint was saved, but it was not assessed.",
                failure_kind="invalid_response",
                diagnostic="malformed JSON",
            ),
        ):
            response = self.client.post(
                "/api/chat",
                json={
                    "message": "A fictional complaint",
                    "session_id": "invalid-model-response",
                },
            )

        self.assertEqual(response.status_code, 503)
        result = response.get_json()
        self.assertEqual(result["failure_kind"], "invalid_response")
        self.assertTrue(result["retry_available"])
        saved = self.client.get(
            "/api/chat-history/invalid-model-response"
        ).get_json()
        self.assertEqual(saved["complaint"], "A fictional complaint")
        self.assertEqual(saved["assessment_status"], "Failed")
        self.assertEqual(saved["analysis"], {})
        self.assertEqual([item["role"] for item in saved["messages"]], ["user"])

    def test_gemini_usage_limit_saves_complaint_and_does_not_create_an_assessment(self):
        message = (
            "Gemini rejected the request because the API account appears to have reached a "
            "usage or billing limit. Your complaint was saved, but it was not assessed."
        )
        with patch.object(
            cyberlegal_app,
            "analyze_complaint",
            side_effect=cyberlegal_app.AnalysisServiceError(
                message,
                code="insufficient_quota",
                failure_kind="billing_limit",
            ),
        ):
            response = self.client.post(
                "/api/chat",
                json={"message": "A complaint", "session_id": "unavailable-analysis"},
            )

        self.assertEqual(response.status_code, 503)
        result = response.get_json()
        self.assertEqual(result["type"], "error")
        self.assertIn("complaint was saved", result["response"])
        self.assertIn("not assessed", result["response"])
        self.assertEqual(result["failure_kind"], "billing_limit")
        self.assertEqual(result["provider_error_code"], "insufficient_quota")
        self.assertEqual(result["session_id"], "unavailable-analysis")
        self.assertEqual(cyberlegal_app.get_chat_session_owner("unavailable-analysis"), 10)

        history = self.client.get("/api/chat-history/unavailable-analysis")
        self.assertEqual(history.status_code, 200)
        saved_session = history.get_json()
        self.assertEqual(saved_session["complaint"], "A complaint")
        self.assertEqual(
            [turn["role"] for turn in saved_session["messages"]],
            ["user"],
        )
        self.assertEqual(saved_session["messages"][0]["message"], "A complaint")
        self.assertEqual(saved_session["status"], "Analysis unavailable")
        self.assertEqual(saved_session["assessment_status"], "Failed")
        self.assertEqual(saved_session["analysis"], {})
        report = self.client.post(
            "/api/reports",
            json={"session_id": "unavailable-analysis"},
        )
        self.assertEqual(report.status_code, 409)

    def test_retry_reuses_saved_complaint_without_duplicate_messages(self):
        transient_error = cyberlegal_app.AnalysisServiceError(
            "Gemini is temporarily unavailable. Your complaint was saved, but it was not assessed.",
            code="503",
            failure_kind="provider_overloaded",
        )
        with patch.object(
            cyberlegal_app,
            "analyze_complaint",
            side_effect=[transient_error, self.analysis()],
        ) as analyzer:
            first = self.client.post(
                "/api/chat",
                json={"message": "A complaint", "session_id": "retry-analysis"},
            )
            self.assertEqual(first.status_code, 503)
            self.assertTrue(first.get_json()["retry_available"])

            before_retry = self.client.get("/api/chat-history/retry-analysis").get_json()
            self.assertEqual(before_retry["status"], "Analysis unavailable")
            self.assertEqual(
                [(turn["role"], turn["message"]) for turn in before_retry["messages"]],
                [("user", "A complaint")],
            )

            retried = self.client.post(
                "/api/chat/retry",
                json={"session_id": "retry-analysis"},
            )
            self.assertEqual(retried.status_code, 200)
            self.assertEqual(retried.get_json()["type"], "final")
            self.assertEqual(analyzer.call_count, 2)

        saved = self.client.get("/api/chat-history/retry-analysis").get_json()
        self.assertEqual(saved["status"], "Complete")
        self.assertEqual(
            [(turn["role"], turn["message"]) for turn in saved["messages"]],
            [
                ("user", "A complaint"),
                ("assistant", "An unauthorized transfer was reported."),
            ],
        )

    def test_repeated_chat_post_after_failure_does_not_duplicate_saved_message(self):
        with patch.object(
            cyberlegal_app,
            "analyze_complaint",
            side_effect=[
                cyberlegal_app.AnalysisServiceError(
                    "Gemini is temporarily unavailable.",
                    failure_kind="provider_overloaded",
                ),
                self.analysis(),
            ],
        ) as analyzer:
            first = self.client.post(
                "/api/chat",
                json={"message": "A complaint", "session_id": "post-retry-dedupe"},
            )
            self.assertEqual(first.status_code, 503)
            second = self.client.post(
                "/api/chat",
                json={"message": "A complaint", "session_id": "post-retry-dedupe"},
            )
            self.assertEqual(second.status_code, 200)
            self.assertEqual(analyzer.call_count, 2)

        saved = self.client.get("/api/chat-history/post-retry-dedupe").get_json()
        self.assertEqual(
            [(turn["role"], turn["message"]) for turn in saved["messages"]],
            [
                ("user", "A complaint"),
                ("assistant", "An unauthorized transfer was reported."),
            ],
        )

    def test_repeated_completed_chat_post_returns_saved_analysis(self):
        with patch.object(cyberlegal_app, "analyze_complaint", return_value=self.analysis()) as analyzer:
            first = self.client.post(
                "/api/chat",
                json={"message": "A complaint", "session_id": "completed-post-dedupe"},
            )
            second = self.client.post(
                "/api/chat",
                json={"message": "A complaint", "session_id": "completed-post-dedupe"},
            )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.get_json()["type"], "final")
        analyzer.assert_called_once()
        saved = self.client.get("/api/chat-history/completed-post-dedupe").get_json()
        self.assertEqual(
            [turn["role"] for turn in saved["messages"]],
            ["user", "assistant"],
        )

    def test_chat_history_search_matches_category_complaint_and_tamil_text(self):
        with patch.object(
            cyberlegal_app,
            "analyze_complaint",
            return_value=self.analysis(
                crime_type="Phishing",
                summary="A suspicious link was reported.",
                indicators=["Suspicious link"],
            ),
        ):
            response = self.client.post(
                "/api/chat",
                json={
                    "message": "என் பெயரில் fake account sent a suspicious link; பணம் lost",
                    "session_id": "searchable-history",
                },
            )
        self.assertEqual(response.status_code, 200)

        for query in ("phishing", "FAKE", "பெயரில்", "suspicious li", "money"):
            with self.subTest(query=query):
                results = self.client.get(
                    "/api/chat-history", query_string={"q": query}
                ).get_json()["sessions"]
                self.assertEqual([item["session_id"] for item in results], ["searchable-history"])

        history_page = self.client.get("/chat-history?q=phishing")
        self.assertEqual(history_page.status_code, 200)
        self.assertIn(b"Phishing", history_page.data)
        self.assertIn(b"Assessed", history_page.data)
        self.assertIn(b"searchable-history", history_page.data)

    def test_new_conversation_does_not_reuse_previous_message_context(self):
        with patch.object(
            cyberlegal_app,
            "analyze_complaint",
            side_effect=[self.analysis(), self.analysis()],
        ) as analyzer:
            first = self.client.post(
                "/api/chat",
                json={"message": "First report details", "session_id": "first-conversation"},
            )
            second = self.client.post(
                "/api/chat",
                json={"message": "Second report details", "session_id": "second-conversation"},
            )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(analyzer.call_args_list[1].args[1], [])
        first_history = self.client.get("/api/chat-history/first-conversation").get_json()
        second_history = self.client.get("/api/chat-history/second-conversation").get_json()
        self.assertEqual(first_history["complaint"], "First report details")
        self.assertEqual(second_history["complaint"], "Second report details")
        self.assertNotEqual(first_history["session_id"], second_history["session_id"])

    def test_chat_history_detail_restores_analysis_and_associated_reports(self):
        with patch.object(cyberlegal_app, "analyze_complaint", return_value=self.analysis()):
            response = self.client.post(
                "/api/chat",
                json={"message": "An unauthorized transfer", "session_id": "saved-detail"},
            )
        self.assertEqual(response.status_code, 200)
        report_response = self.client.post(
            "/api/reports",
            json={"session_id": "saved-detail"},
        )
        self.assertEqual(report_response.status_code, 201)
        report_ref = report_response.get_json()["report_ref"]
        for query in (report_ref.lower(), str(report_response.get_json()["report_id"])):
            with self.subTest(report_query=query):
                results = self.client.get(
                    "/api/chat-history", query_string={"q": query}
                ).get_json()["sessions"]
                self.assertEqual([item["session_id"] for item in results], ["saved-detail"])

        detail = self.client.get("/api/chat-history/saved-detail").get_json()
        self.assertEqual(detail["title"], "An unauthorized transfer")
        self.assertEqual(detail["analysis"]["type"], "final")
        self.assertEqual(detail["assessment_status"], "Assessed")
        self.assertTrue(detail["updated_at"])
        self.assertIn("unauthorized", detail["keywords"])
        self.assertEqual(detail["related_reports"][0]["id"], report_response.get_json()["report_id"])

    def test_repeated_report_save_returns_the_existing_report(self):
        with patch.object(cyberlegal_app, "analyze_complaint", return_value=self.analysis()):
            self.client.post(
                "/api/chat",
                json={"message": "An unauthorized transfer", "session_id": "report-dedupe"},
            )

        first = self.client.post("/api/reports", json={"session_id": "report-dedupe"})
        second = self.client.post("/api/reports", json={"session_id": "report-dedupe"})
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.get_json()["report_id"], second.get_json()["report_id"])
        self.assertEqual(len(cyberlegal_app.fetch_reports(10)), 1)

    def test_another_users_chat_cannot_be_searched_or_opened(self):
        cyberlegal_app.create_chat_session(
            "private-history-search", "private phishing complaint", "English", user_id=999
        )
        search = self.client.get(
            "/api/chat-history", query_string={"q": "private phishing"}
        ).get_json()["sessions"]
        self.assertEqual(search, [])
        detail = self.client.get("/api/chat-history/private-history-search")
        self.assertEqual(detail.status_code, 404)

    def test_legacy_chat_metadata_is_backfilled_without_replacing_messages(self):
        cyberlegal_app.create_chat_session(
            "legacy-chat-metadata", "A suspicious payment link", "English", user_id=10
        )
        connection, _ = cyberlegal_app.get_db_connection()
        try:
            connection.execute(
                "UPDATE chat_sessions SET keywords = '[]', analysis_json = ? WHERE session_id = ?",
                (
                    '{"category":"Phishing","summary":"A phishing link was reported."}',
                    "legacy-chat-metadata",
                ),
            )
            connection.commit()
        finally:
            connection.close()
        cyberlegal_app.save_chat_message(
            "legacy-chat-metadata", "user", "A suspicious payment link"
        )

        cyberlegal_app.ensure_chat_session_columns()
        detail = self.client.get("/api/chat-history/legacy-chat-metadata").get_json()
        self.assertIn("phishing", detail["keywords"])
        self.assertEqual(len(detail["messages"]), 1)
        self.assertEqual(detail["messages"][0]["message"], "A suspicious payment link")

    def test_duplicate_post_is_rejected_while_analysis_is_pending(self):
        cyberlegal_app.create_chat_session(
            "pending-post-dedupe", "A complaint", "English", user_id=10
        )
        cyberlegal_app.save_chat_message(
            "pending-post-dedupe", "user", "A complaint"
        )
        cyberlegal_app.update_chat_session_analysis(
            "pending-post-dedupe",
            "Unassessed",
            0,
            "Analysis pending",
            "English",
            {},
        )
        with patch.object(cyberlegal_app, "analyze_complaint") as analyzer:
            response = self.client.post(
                "/api/chat",
                json={"message": "A complaint", "session_id": "pending-post-dedupe"},
            )
        self.assertEqual(response.status_code, 409)
        analyzer.assert_not_called()
        saved = self.client.get("/api/chat-history/pending-post-dedupe").get_json()
        self.assertEqual([turn["role"] for turn in saved["messages"]], ["user"])

    def test_retry_after_failed_follow_up_keeps_conversation_context(self):
        follow_up = self.analysis(
            response_type="follow_up",
            follow_up_question="Was money transferred?",
            missing_information=["Whether money was transferred."],
        )
        transient_error = cyberlegal_app.AnalysisServiceError(
            "Gemini is temporarily unavailable.",
            code="503",
            failure_kind="provider_overloaded",
        )
        with patch.object(
            cyberlegal_app,
            "analyze_complaint",
            side_effect=[follow_up, transient_error, self.analysis()],
        ) as analyzer:
            first = self.client.post(
                "/api/chat",
                json={"message": "A suspicious support call", "session_id": "retry-follow-up"},
            )
            self.assertEqual(first.status_code, 200)
            failed = self.client.post(
                "/api/chat",
                json={"message": "Yes", "session_id": "retry-follow-up"},
            )
            self.assertEqual(failed.status_code, 503)
            self.assertEqual(
                self.client.get("/api/chat-history/retry-follow-up").get_json()["status"],
                "Analysis unavailable",
            )

            retried = self.client.post(
                "/api/chat/retry",
                json={"session_id": "retry-follow-up"},
            )
            self.assertEqual(retried.status_code, 200)
            self.assertEqual(retried.get_json()["type"], "final")
            retry_context = analyzer.call_args_list[2].args[1]
            self.assertEqual(retry_context[-1]["content"], "Was money transferred?")

        saved = self.client.get("/api/chat-history/retry-follow-up").get_json()
        self.assertEqual(
            [turn["role"] for turn in saved["messages"]],
            ["user", "assistant", "user", "assistant"],
        )
        self.assertEqual(saved["messages"][2]["message"], "Yes")

    def test_retry_route_rejects_another_users_session_and_duplicate_retry(self):
        cyberlegal_app.create_chat_session(
            "another-owner-retry", "A complaint", "English", user_id=999
        )
        forbidden = self.client.post(
            "/api/chat/retry",
            json={"session_id": "another-owner-retry"},
        )
        self.assertEqual(forbidden.status_code, 404)

        with patch.object(
            cyberlegal_app,
            "analyze_complaint",
            side_effect=cyberlegal_app.AnalysisServiceError(
                "Gemini is temporarily unavailable.",
                failure_kind="provider_overloaded",
            ),
        ):
            self.client.post(
                "/api/chat",
                json={"message": "A complaint", "session_id": "single-retry"},
            )
        with patch.object(cyberlegal_app, "analyze_complaint", return_value=self.analysis()) as analyzer:
            first = self.client.post("/api/chat/retry", json={"session_id": "single-retry"})
            second = self.client.post("/api/chat/retry", json={"session_id": "single-retry"})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 409)
        analyzer.assert_called_once()

    def test_configuration_failure_is_saved_without_retrying_or_assessment(self):
        with patch.object(
            cyberlegal_app,
            "analyze_complaint",
            side_effect=cyberlegal_app.AnalysisConfigurationError(
                "The configured Gemini model is unavailable.",
                failure_kind="invalid_model",
            ),
        ) as analyzer:
            response = self.client.post(
                "/api/chat",
                json={"message": "A complaint", "session_id": "unsupported-model"},
            )
        result = response.get_json()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(result["type"], "error")
        self.assertFalse(result["retry_available"])
        self.assertIn("complaint was saved", result["response"])
        self.assertEqual(analyzer.call_count, 1)
        saved = self.client.get("/api/chat-history/unsupported-model").get_json()
        self.assertEqual(saved["status"], "Analysis unavailable")
        self.assertEqual(saved["analysis"], {})
        self.assertEqual([turn["role"] for turn in saved["messages"]], ["user"])

    def test_unexpected_provider_exception_does_not_leave_session_pending(self):
        with patch.object(
            cyberlegal_app,
            "analyze_complaint",
            side_effect=RuntimeError("unexpected provider response"),
        ):
            response = self.client.post(
                "/api/chat",
                json={"message": "A complaint", "session_id": "unexpected-provider-error"},
            )
        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.get_json()["retry_available"])
        self.assertIn("not assessed", response.get_json()["response"])
        saved = self.client.get("/api/chat-history/unexpected-provider-error").get_json()
        self.assertEqual(saved["status"], "Analysis unavailable")
        self.assertEqual(saved["analysis"], {})
        self.assertEqual([turn["role"] for turn in saved["messages"]], ["user"])

    def test_security_incident_without_secret_value_is_allowed(self):
        self.assertFalse(cyberlegal_app._contains_authentication_secret(
            "My password was compromised after my account was hacked."
        ))


if __name__ == "__main__":
    unittest.main()
