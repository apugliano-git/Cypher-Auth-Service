import unittest
from pathlib import Path
import subprocess
import sys
import tempfile
from evidence import findings, redact, summary


class EvidencePrivacyTest(unittest.TestCase):
    def test_generated_password_is_removed_without_losing_test_result(self):
        text = "Using generated security password: fixture-only-value\n[ERROR] Tests run: 1, Failures: 1\n"
        self.assertNotIn("fixture-only-value", redact(text))
        self.assertIn("Tests run: 1, Failures: 1", redact(text))
        self.assertEqual([1], findings(text))
        self.assertEqual([], findings(redact(text)))

    def test_rejected_password_and_refresh_values_are_removed(self):
        for field in ("password", "refresh_token"):
            text = f"field '{field}': rejected value [fixture-only-value]; validation failed\n"
            self.assertNotIn("fixture-only-value", redact(text))
            self.assertEqual([1], findings(text))

    def test_multiline_credentials_do_not_survive_redaction(self):
        sensitive = "synthetic-" + str(42)
        for text in ("field 'password': rejected value [\n" + sensitive + "]; failed\n[INFO] BUILD FAILURE\n",
                     'password="\n' + sensitive + '"\n[INFO] BUILD FAILURE\n'):
            self.assertNotIn(sensitive, redact(text))
            self.assertIn("BUILD FAILURE", redact(text))
            self.assertTrue(findings(text))

    def test_assignments_authorization_and_private_keys_are_rejected(self):
        for text in ('{"password":"fixture-only-value"}', '--cypher.jwt.keystore.password=fixture-only-value',
                     'Authorization: Bearer fixture-only-value', 'Authorization: Basic fixture-only-value',
                     '-----BEGIN PRIVATE KEY-----\nfixture-only-value\n-----END PRIVATE KEY-----'):
            self.assertTrue(findings(text))
            self.assertNotIn("fixture-only-value", redact(text))
            self.assertEqual([], findings(redact(text)))

    def test_sanitized_output_is_idempotent_and_normal_logs_are_preserved(self):
        text = "[INFO] BUILD SUCCESS\n[REDACTED credential-bearing log line]\n"
        self.assertEqual(text, redact(text))
        self.assertEqual([], findings(text))

    def test_public_summary_drops_arbitrary_logs_and_preserves_build_failure(self):
        sensitive = "synthetic-" + str(42)
        text = sensitive + "\n[INFO] Tests run: 2, Failures: 1, Errors: 0, Skipped: 0\n[INFO] BUILD FAILURE\n"
        self.assertEqual("[INFO] Tests run: 2, Failures: 1, Errors: 0, Skipped: 0\n[INFO] BUILD FAILURE\n", summary(text))
        self.assertEqual("", summary("[INFO] BUILD SUCCESS " + sensitive + "\n"))

    def test_cli_rejects_without_echoing_values_and_sanitizes_explicit_log(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "run.log"
            sensitive = "synthetic-" + str(42)
            path.write_text("Using generated security password: " + sensitive + "\n[INFO] BUILD FAILURE\n")
            command = [sys.executable, str(Path(__file__).with_name("evidence.py"))]
            rejected = subprocess.run(command + [folder], capture_output=True, text=True)
            self.assertEqual(1, rejected.returncode)
            self.assertNotIn(sensitive, rejected.stdout + rejected.stderr)
            public = subprocess.run(command + ["--summary", str(path)], capture_output=True, text=True)
            self.assertEqual(0, public.returncode)
            self.assertEqual("[INFO] BUILD FAILURE\n", public.stdout)
            self.assertNotIn(sensitive, public.stdout + public.stderr)
            self.assertEqual(0, subprocess.run(command + ["--redact", str(path)], capture_output=True).returncode)
            self.assertEqual(0, subprocess.run(command + [folder], capture_output=True).returncode)
            self.assertIn("BUILD FAILURE", path.read_text())


if __name__ == "__main__":
    unittest.main()
