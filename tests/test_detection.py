import unittest

from src.detectors import detect_threats
from src.config import DetectionSettings
from src.intelligence import enrich_alerts
from src.story import build_attack_story
from src.utils import extract_ip, parse_log_text


class ThreatLensDetectionTests(unittest.TestCase):
    def test_validates_ip_addresses(self):
        self.assertEqual(extract_ip("source 45.33.12.9 connected"), "45.33.12.9")
        self.assertIsNone(extract_ip("source 999.999.999.999 connected"))

    def test_detects_demo_auth_patterns(self):
        lines = [
            f"Jan 20 22:40:{second:02d} server sshd[101]: Failed password for invalid user user{second} from 45.33.12.9 port 51422 ssh2"
            for second in range(1, 10)
        ]
        df = parse_log_text("\n".join(lines))
        alerts = detect_threats(df)

        self.assertIn("Brute Force Attempt", alerts["type"].tolist())
        self.assertIn("Credential Stuffing Pattern", alerts["type"].tolist())

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


if __name__ == "__main__":
    unittest.main()
