"""Regression checks that SecureLink never re-enables paid HIBP lookups by accident."""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


class PaidHibpDisabledTests(unittest.TestCase):
    def test_runtime_has_no_paid_hibp_credentials_or_endpoints(self):
        runtime_files = [
            REPO_ROOT / "app.py",
            REPO_ROOT / "config.py",
            REPO_ROOT / "features.py",
            REPO_ROOT / "dark_web_monitor.py",
            REPO_ROOT / ".env.docker.example",
        ]
        runtime = "\n".join(path.read_text(encoding="utf-8") for path in runtime_files)
        lowered = runtime.lower()

        self.assertNotIn("hibp_api_key", lowered)
        self.assertNotIn("api/v3/breachedaccount", lowered)
        self.assertNotIn("api/v3/pasteaccount", lowered)
        self.assertNotIn("haveibeenpwned.com/api", lowered)

    def test_only_password_range_api_is_configured(self):
        monitor = (REPO_ROOT / "dark_web_monitor.py").read_text(encoding="utf-8")
        self.assertIn("https://api.pwnedpasswords.com", monitor)
        self.assertIn("/range/{prefix}", monitor)


if __name__ == "__main__":
    unittest.main()
