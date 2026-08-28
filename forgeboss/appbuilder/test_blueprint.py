from __future__ import annotations

import json
import unittest

from forgeboss.appbuilder.blueprint import compile_blueprint, detect_capabilities, infer_template


class BlueprintTests(unittest.TestCase):
    def test_siteboss_style_request_compiles_to_web_saas(self):
        idea = (
            "Build me SiteBoss, a SaaS for fencing businesses with CRM, scheduling, "
            "AI receptionist, Stripe billing, login and an owner dashboard."
        )
        result = compile_blueprint(idea)
        self.assertEqual(result["app"]["name"], "SiteBoss")
        self.assertEqual(result["app"]["template"], "web-saas")
        self.assertTrue({"ai", "authentication", "payments", "scheduling", "admin", "database"} <= set(result["capabilities"]))
        self.assertTrue(result["controller_contract"]["must_materialize_exact_file_scopes_before_execution"])
        json.dumps(result)

    def test_mobile_inference(self):
        self.assertEqual(infer_template("Create an Android and iPhone mobile app for tradies"), "expo-mobile")

    def test_api_inference(self):
        self.assertEqual(infer_template("Create a REST API for invoice calculations"), "api-service")

    def test_website_inference(self):
        self.assertEqual(infer_template("Create a marketing site and landing page for a builder"), "website")

    def test_override_and_determinism(self):
        kwargs = dict(
            name="Example",
            template="web-saas",
            constraints=["No automatic deploy", "Australia only"],
            capabilities=["files"],
            stack_overrides={"backend": "FastAPI"},
        )
        a = compile_blueprint("Build an app for job tracking", **kwargs)
        b = compile_blueprint("Build an app for job tracking", **kwargs)
        self.assertEqual(a, b)
        self.assertEqual(a["stack"]["backend"], "FastAPI")
        self.assertEqual(a["blueprint_id"], b["blueprint_id"])

    def test_invalid_template_fails_closed(self):
        with self.assertRaises(ValueError):
            compile_blueprint("Build something", template="made-up")

    def test_capability_detection_adds_database_dependency(self):
        caps = detect_capabilities("Need login and Stripe checkout")
        self.assertIn("authentication", caps)
        self.assertIn("payments", caps)
        self.assertIn("database", caps)

    def test_release_workstream_is_review_only(self):
        result = compile_blueprint("Build a customer portal", name="Portal")
        release = result["workstreams"][-1]
        self.assertEqual(release["id"], "release-readiness")
        self.assertIn("read-only", " ".join(release["scope"]))
        self.assertTrue(result["controller_contract"]["must_not_auto_deploy"])


if __name__ == "__main__":
    unittest.main()
