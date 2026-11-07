"""Unit tests for pulse-infragraph core helpers."""
import json
import tempfile
import unittest
from pathlib import Path

from core.engine import normalize_domain
from core.exporter import export_bugbounty_json, export_csv, export_nuclei_txt
from core.history import compare_scans, load_history, save_scan
from core.risk import calculate_risk


class DomainValidationTests(unittest.TestCase):
    def test_normalizes_domain(self):
        self.assertEqual(normalize_domain(" Example.COM. "), "example.com")

    def test_rejects_url_and_ip(self):
        for value in ("https://example.com", "127.0.0.1", "*.example.com", "example.com/path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)


class RiskTests(unittest.TestCase):
    def test_keyword_and_wordpress_signals_are_explained(self):
        result = calculate_risk("staging.example.com", ["WordPress"])
        self.assertEqual(result["score"], 60)
        self.assertEqual(result["level"], "CRITICAL")
        self.assertEqual(len(result["reasons"]), 2)

    def test_score_is_capped(self):
        result = calculate_risk("admin-dev.example.com", ["WordPress"], [80, 443])
        self.assertLessEqual(result["score"], 100)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "domain": "example.com",
            "assets": [{
                "domain": "example.com",
                "subdomain": "www.example.com",
                "risk": {"score": 0, "level": "SAFE"},
                "fingerprint": {"status": 200, "technologies": ["Nginx"]},
            }],
        }

    def test_json_and_csv_exports(self):
        self.assertEqual(json.loads(export_bugbounty_json(self.data))["domain"], "example.com")
        self.assertIn("www.example.com", export_csv(self.data))
        self.assertIn("Nginx", export_csv(self.data))

    def test_host_export_deduplicates(self):
        self.assertEqual(export_nuclei_txt(["a.example.com", "a.example.com"]), "a.example.com\n")


class HistoryTests(unittest.TestCase):
    def test_save_and_compare_snapshots(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "history.json"
            save_scan({
                "domain": "example.com", "timestamp": "2026-01-01T00:00:00Z",
                "assets": [{"subdomain": "www.example.com", "risk": {"score": 10, "level": "SAFE"}}],
            }, path)
            save_scan({
                "domain": "example.com", "timestamp": "2026-01-02T00:00:00Z",
                "assets": [
                    {"subdomain": "www.example.com", "risk": {"score": 20, "level": "SAFE"}},
                    {"subdomain": "api.example.com", "risk": {"score": 40, "level": "EXPOSED"}},
                ],
            }, path)
            history = load_history(path)
            self.assertEqual(len(history), 2)
            self.assertEqual(compare_scans(history), {
                "new_assets": 1, "removed_assets": 0, "risk_score_delta": 50,
            })


if __name__ == "__main__":
    unittest.main()
