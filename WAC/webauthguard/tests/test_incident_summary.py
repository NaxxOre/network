import os
import sys
import unittest


HERE = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.incident_summary import fetch_incident_summary, summarize_incidents_from_hits  # noqa: E402


class IncidentSummaryTests(unittest.TestCase):
    def test_empty_events_returns_none_severity(self):
        summary = summarize_incidents_from_hits(hits=[], window_minutes=15)
        self.assertEqual(summary["total_events"], 0)
        self.assertEqual(summary["threat_events"], 0)
        self.assertEqual(summary["severity"], "none")
        self.assertTrue(summary["summary_text"])

    def test_mixed_events_produce_summary_and_counts(self):
        hits = [
            {
                "_source": {
                    "src_ip": "192.168.1.54",
                    "agent": {"username": "admin"},
                    "security": {
                        "possible_threat": True,
                        "threat_score": 65,
                        "threat_types": ["credential_stuffing", "distributed_account_attack"],
                    },
                }
            },
            {
                "_source": {
                    "src_ip": "192.168.1.54",
                    "agent": {"username": "alice"},
                    "security": {
                        "possible_threat": True,
                        "threat_score": 35,
                        "threat_types": ["brute_force"],
                    },
                }
            },
            {
                "_source": {
                    "src_ip": "192.168.1.60",
                    "agent": {"username": "bob"},
                    "security": {"possible_threat": False, "threat_score": 0, "threat_types": []},
                }
            },
        ]

        summary = summarize_incidents_from_hits(hits=hits, window_minutes=20, run_id="demo-1")
        self.assertEqual(summary["window_minutes"], 20)
        self.assertEqual(summary["run_id"], "demo-1")
        self.assertEqual(summary["total_events"], 3)
        self.assertEqual(summary["threat_events"], 2)
        self.assertEqual(summary["max_threat_score"], 65)
        self.assertEqual(summary["severity"], "medium")
        self.assertGreaterEqual(len(summary["top_threat_types"]), 1)
        self.assertTrue(summary["summary_text"])
        self.assertGreaterEqual(len(summary["recommended_actions"]), 1)

    def test_run_id_is_carried_into_response(self):
        hits = [{"_source": {"src_ip": "127.0.0.1", "agent": {}, "security": {}}}]
        summary = summarize_incidents_from_hits(hits=hits, window_minutes=5, run_id="run-xyz")
        self.assertEqual(summary["run_id"], "run-xyz")

    def test_fetch_incident_summary_adds_run_id_filter(self):
        class FakeClient:
            def __init__(self):
                self.last_index = None
                self.last_body = None

            def search(self, index, body):
                self.last_index = index
                self.last_body = body
                return {"hits": {"hits": []}}

        fake = FakeClient()
        summary = fetch_incident_summary(fake, window_minutes=30, run_id="campaign-1")

        self.assertEqual(fake.last_index, "webauthguard-events-*")
        self.assertEqual(summary["run_id"], "campaign-1")
        filters = fake.last_body["query"]["bool"]["filter"]
        self.assertTrue(any(f.get("term", {}).get("demo.run_id.keyword") == "campaign-1" for f in filters))


if __name__ == "__main__":
    unittest.main()
