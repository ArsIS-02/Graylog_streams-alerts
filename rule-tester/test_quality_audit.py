#!/usr/bin/env python3
"""Проверки внутренней группировки кандидатов на тюнинг по закрытиям IRIS."""
import json
import unittest

import quality_audit as qa


class ObservableTest(unittest.TestCase):
    def test_fields_have_priority_over_graylog_source(self):
        row = {"alert_source_content": json.dumps({
            "source": "graylog.example.test",
            "fields": {
                "wazuh_agent": "endpoint.example.test",
                "acct": "analyst",
                "process_command_line": "/usr/bin/systemctl restart demo.service",
                "unrelated": "не должно попасть в результат",
            },
        }, ensure_ascii=False)}
        self.assertEqual(qa.iris_observables(row), {
            "host": "endpoint.example.test",
            "user": "analyst",
            "command": "/usr/bin/systemctl restart demo.service",
        })

    def test_missing_fields_are_explicit(self):
        row = {"alert_source_content": {"source": "aggregator.example.test", "fields": {}}}
        self.assertEqual(qa.iris_observables(row), {
            "host": "aggregator.example.test",
            "user": qa.UNKNOWN_FIELD,
            "command": qa.UNKNOWN_FIELD,
        })

    def test_invalid_content_does_not_break_collection(self):
        self.assertEqual(qa.iris_observables({"alert_source_content": "not-json"}), {
            "host": qa.UNKNOWN_FIELD,
            "user": qa.UNKNOWN_FIELD,
            "command": qa.UNKNOWN_FIELD,
        })


class CandidateTest(unittest.TestCase):
    @staticmethod
    def alert(identifier, resolution="False Positive", closed="2026-11-20T10:00:00+05:00",
              host="endpoint.example.test"):
        return {
            "id": identifier,
            "rule": "WAZUH - Важный алерт (уровень 9-11)",
            "resolution": resolution,
            "closed_at": closed,
            "host": host,
            "user": qa.UNKNOWN_FIELD,
            "command": qa.UNKNOWN_FIELD,
        }

    def test_only_fp_and_legitimate_are_grouped(self):
        rows = [
            self.alert(1),
            self.alert(2, resolution="Legitimate", closed="2026-11-20T11:00:00+05:00"),
            self.alert(3, resolution="True Positive With Impact"),
            self.alert(4, resolution="Unknown"),
        ]
        groups = qa.tuning_candidates(rows)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["count"], 2)
        self.assertEqual(groups[0]["resolutions"], {"False Positive": 1, "Legitimate": 1})
        self.assertEqual(groups[0]["last_closed_at"], "2026-11-20T11:00:00+05:00")
        self.assertEqual(groups[0]["alert_ids"], [1, 2])
        self.assertIn("Повтор", groups[0]["recommendation"])
        self.assertIn("ручного разбора", groups[0]["recommendation"])

    def test_single_closure_requires_observation(self):
        groups = qa.tuning_candidates([self.alert(10)])
        self.assertEqual(groups[0]["count"], 1)
        self.assertIn("наблюдение", groups[0]["recommendation"])
        self.assertIn("автоматически не менять", groups[0]["recommendation"])

    def test_dimensions_and_sorting_are_stable(self):
        rows = [self.alert(1, host="host-b"), self.alert(2, host="host-a"),
                self.alert(3, host="host-a")]
        groups = qa.tuning_candidates(rows)
        self.assertEqual([(row["host"], row["count"]) for row in groups],
                         [("host-a", 2), ("host-b", 1)])


if __name__ == "__main__":
    unittest.main()
