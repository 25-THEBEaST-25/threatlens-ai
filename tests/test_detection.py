import unittest

from src.detectors import detect_threats
from src.config import DetectionSettings
from src.ioc import extract_iocs, summarize_ioc_counts
from src.intelligence import enrich_alerts
from src.reports import build_json_report
from src.story import build_attack_story
from src.utils import extract_ip, parse_log_text


class ThreatLensDetectionTests(unittest.TestCase):
    def test_validates_ip_addresses(self):
        self.assertEqual(extract_ip("source 45.33.12.9 connected"), "45.33.12.9")
        self.assertIsNone(extract_ip("source 999.999.999.999 connected"))

    def test_detects_demo_auth_patterns(self):
        lines = [
            f"Jan 20 22:40:{second:02d} server sshd[101]: Failed password for invalid user user{second} from 45.33.12.9 port 51422 ssh2"
            for second in range(1, 14)
        ]
        df = parse_log_text("\n".join(lines))
        alerts = detect_threats(df)

        self.assertIn("Brute Force Attempt", alerts["type"].tolist())
        self.assertIn("Credential Stuffing Pattern", alerts["type"].tolist())
        brute_force = alerts[alerts["type"] == "Brute Force Attempt"].iloc[0]
        self.assertEqual(brute_force["mitre"], {"id": "T1110", "name": "Brute Force"})
        self.assertEqual(brute_force["severity"], "HIGH")
        self.assertEqual(brute_force["confidence"], "High")
        self.assertIn("risk_score", alerts.columns)
        self.assertIn("confidence_score", alerts.columns)

    def test_detects_nginx_endpoint_probing(self):
        log_text = "\n".join(
            [
                '127.0.0.1 - - [23/Jan/2026:10:25:01 +0530] "GET /admin HTTP/1.1" 404 -',
                '127.0.0.1 - - [23/Jan/2026:10:25:03 +0530] "GET /wp-login.php HTTP/1.1" 404 -',
                '127.0.0.1 - - [23/Jan/2026:10:25:05 +0530] "GET /.env HTTP/1.1" 403 -',
            ]
        )
        df = parse_log_text(log_text)
        alerts = detect_threats(df)

        self.assertIn("Suspicious Endpoint Probing", alerts["type"].tolist())

    def test_detects_success_after_failures(self):
        log_text = "\n".join(
            [
                f"2026-01-23 10:21:{second:02d} Failed login user=admin from 45.33.12.9"
                for second in range(1, 7)
            ]
            + ["2026-01-23 10:22:01 Login successful user=admin from 45.33.12.9"]
        )
        alerts = detect_threats(parse_log_text(log_text))

        self.assertIn("Successful Login After Failures", alerts["type"].tolist())

    def test_allowlist_suppresses_alerts(self):
        log_text = "\n".join(
            [
                f"2026-01-23 10:21:{second:02d} Failed login user=admin from 45.33.12.9"
                for second in range(1, 10)
            ]
        )
        settings = DetectionSettings(allowlisted_ips=("45.33.12.9",))
        alerts = detect_threats(parse_log_text(log_text), settings=settings)

        self.assertTrue(alerts.empty)

    def test_json_log_parsing_and_story(self):
        log_text = "\n".join(
            [
                '{"event_type":"failed_login","src_ip":"198.51.100.10","username":"root"}',
                '{"event_type":"failed_login","src_ip":"198.51.100.10","username":"admin"}',
                '{"event_type":"failed_login","src_ip":"198.51.100.10","username":"guest"}',
                '{"event_type":"failed_login","src_ip":"198.51.100.10","username":"dev"}',
                '{"event_type":"failed_login","src_ip":"198.51.100.10","username":"ops"}',
                '{"event_type":"failed_login","src_ip":"198.51.100.10","username":"test"}',
                '{"event_type":"failed_login","src_ip":"198.51.100.10","username":"demo"}',
                '{"event_type":"failed_login","src_ip":"198.51.100.10","username":"service"}',
            ]
        )
        df = parse_log_text(log_text)
        alerts = enrich_alerts(detect_threats(df), df)
        story = build_attack_story(df, alerts)

        self.assertEqual(df.iloc[0]["format"], "json")
        self.assertIn("Credential Stuffing Pattern", alerts["type"].tolist())
        self.assertTrue(any("Primary suspect" in line for line in story))

    def test_extracts_iocs(self):
        log_text = (
            '2026-01-23 10:21:01 Failed login user=admin from 45.33.12.9 '
            'request="GET /admin HTTP/1.1" url=https://example.test/login'
        )
        df = parse_log_text(log_text)
        iocs = extract_iocs(log_text, df)
        counts = summarize_ioc_counts(iocs)

        self.assertIn({"Indicator": "45.33.12.9", "Type": "IP Address"}, iocs.to_dict(orient="records"))
        self.assertIn({"Indicator": "admin", "Type": "Username"}, iocs.to_dict(orient="records"))
        self.assertIn({"Indicator": "/admin", "Type": "Endpoint"}, iocs.to_dict(orient="records"))
        self.assertEqual(counts["Unique IPs"], 1)
        self.assertEqual(counts["Endpoints"], 1)
        self.assertEqual(counts["Usernames"], 1)

    def test_builds_json_report(self):
        log_text = "\n".join(
            [
                f"2026-01-23 10:21:{second:02d} Failed login user=admin from 45.33.12.9"
                for second in range(1, 10)
            ]
        )
        df = parse_log_text(log_text)
        alerts = enrich_alerts(detect_threats(df), df)
        iocs = extract_iocs(log_text, df)
        report = build_json_report({"total_events": len(df)}, alerts, iocs)

        self.assertIn('"summary"', report)
        self.assertIn('"alerts"', report)
        self.assertIn('"ioc_data"', report)
        self.assertIn('"mitre"', report)


if __name__ == "__main__":
    unittest.main()
