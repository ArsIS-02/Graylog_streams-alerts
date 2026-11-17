#!/usr/bin/env python3
"""Проверки диапазонов Lucene и оценки FP-check по типам правил."""
import json
import unittest

import lucene as L
import rule_tester as rt


def rule(title="TEST", query="source:host", **overrides):
    value = {
        "title": title, "query": query, "streams": ["Logs"], "group_by": [],
        "cond": None, "priority": 2, "window_min": 5,
    }
    value.update(overrides)
    return value


def doc(minute=0, source="host", level=10):
    return {
        "timestamp": "2026-11-17T10:%02d:00Z" % minute,
        "source": source,
        "rule_level": level,
    }


class NumericRangeTest(unittest.TestCase):
    def test_inclusive_range_boundaries(self):
        node, _ = L.parse("rule_level:[9 TO 11]")
        self.assertTrue(L.evaluate(node, doc(level=9)))
        self.assertTrue(L.evaluate(node, doc(level="11")))
        self.assertFalse(L.evaluate(node, doc(level=8)))
        self.assertFalse(L.evaluate(node, doc(level=12)))

    def test_unbounded_and_exclusive_ranges(self):
        unbounded, _ = L.parse("rule_level:[3 TO *]")
        exclusive, _ = L.parse("rule_level:{3 TO 5}")
        mixed, _ = L.parse("rule_level:[3 TO 5}")
        self.assertTrue(L.evaluate(unbounded, doc(level=100)))
        self.assertFalse(L.evaluate(unbounded, doc(level=2)))
        self.assertFalse(L.evaluate(exclusive, doc(level=3)))
        self.assertTrue(L.evaluate(exclusive, doc(level=4)))
        self.assertFalse(L.evaluate(exclusive, doc(level=5)))
        self.assertTrue(L.evaluate(mixed, doc(level=3)))
        self.assertFalse(L.evaluate(mixed, doc(level=5)))

    def test_range_sample_is_valid(self):
        node, _ = L.parse("tool:wazuh AND rule_level:[12 TO 15]")
        positive, _, problems = L.make_samples(node)
        self.assertFalse(problems)
        self.assertTrue(positive)
        self.assertTrue(L.evaluate(node, positive[0]["doc"]))

    def test_non_numeric_range_is_rejected_clearly(self):
        with self.assertRaisesRegex(L.QueryError, "числовые диапазоны"):
            L.parse("source:[a TO z]")


class FpCheckTest(unittest.TestCase):
    def test_single_event_match_is_candidate(self):
        row = rt.fp_check_rule(rule(), [doc()])
        self.assertEqual(row["status"], "ЕСТЬ СОВПАДЕНИЯ")
        self.assertEqual(row["kind"], "событие")

    def test_informational_digest_is_not_false_positive(self):
        row = rt.fp_check_rule(rule(title="KEENETIC - Отказы WireGuard (ежедневная сводка)",
                                    cond={"op": ">=", "value": 1}), [doc(), doc()])
        self.assertEqual(row["status"], "НЕ ПРИМЕНИМО")
        self.assertEqual(row["kind"], "сводка")

    def test_silence_match_is_not_false_positive(self):
        row = rt.fp_check_rule(rule(cond={"op": "<", "value": 1}), [doc()])
        self.assertEqual(row["status"], "НЕ ПРИМЕНИМО")
        self.assertEqual(row["kind"], "тишина")

    def test_aggregation_below_threshold_is_clean(self):
        r = rule(cond={"op": ">=", "value": 5}, group_by=["source"])
        row = rt.fp_check_rule(r, [doc(minute=0)] * 4)
        self.assertEqual(row["status"], "ЧИСТО")
        self.assertEqual(row["match_count"], 4)
        self.assertEqual(row["aggregation"]["count"], 4)

    def test_aggregation_threshold_is_candidate_and_json_safe(self):
        r = rule(cond={"op": ">=", "value": 5}, group_by=["source"])
        row = rt.fp_check_rule(r, [doc(minute=0)] * 5)
        self.assertEqual(row["status"], "ЕСТЬ СОВПАДЕНИЯ")
        self.assertEqual(row["aggregation"]["count"], 5)
        json.dumps(row)

    def test_groups_are_not_combined(self):
        r = rule(query="source:(host-a OR host-b)", cond={"op": ">=", "value": 5}, group_by=["source"])
        corpus = [doc(source="host-a")] * 3 + [doc(source="host-b")] * 3
        row = rt.fp_check_rule(r, corpus)
        self.assertEqual(row["status"], "ЧИСТО")
        self.assertEqual(row["aggregation"]["count"], 3)

    def test_windows_are_not_combined(self):
        r = rule(cond={"op": ">=", "value": 5}, group_by=["source"])
        corpus = [doc(minute=0)] * 3 + [doc(minute=10)] * 3
        row = rt.fp_check_rule(r, corpus)
        self.assertEqual(row["status"], "ЧИСТО")
        self.assertEqual(row["aggregation"]["count"], 3)

    def test_aggregation_without_timestamps_is_not_guessed(self):
        r = rule(cond={"op": ">=", "value": 5})
        corpus = [{"source": "host"}] * 5
        row = rt.fp_check_rule(r, corpus)
        self.assertEqual(row["status"], "НЕ ПРИМЕНИМО")
        self.assertIn("timestamp", row["detail"])

    @staticmethod
    def composite_condition(count=5, field="winlogbeat_event_code"):
        return rt.cond_of({"expression": {
            "expr": "&&",
            "left": {"expr": ">=", "left": {"expr": "number-ref", "ref": "count-"},
                     "right": {"expr": "number", "value": count}},
            "right": {"expr": ">=", "left": {"expr": "number-ref", "ref": "card-" + field},
                      "right": {"expr": "number", "value": 2}},
        }})

    def test_composite_condition_normalization(self):
        cond = self.composite_condition()
        self.assertEqual(cond["op"], "&&")
        self.assertEqual(cond["left"]["ref"], "count-")
        self.assertEqual(cond["right"]["ref"], "card-winlogbeat_event_code")
        self.assertEqual(rt.threshold(cond), 5)
        self.assertEqual(rt.fp_rule_kind(rule(cond=cond)), "агрегация")

    def test_composite_requires_both_count_and_cardinality(self):
        cond = self.composite_condition()
        corpus = [dict(doc(), winlogbeat_event_code=4624) for _ in range(5)]
        row = rt.fp_check_rule(rule(cond=cond), corpus)
        self.assertEqual(row["status"], "ЧИСТО")
        self.assertEqual(row["aggregation"]["metrics"]["card-winlogbeat_event_code"], 1)

    def test_composite_failure_and_success_is_candidate(self):
        cond = self.composite_condition()
        corpus = [dict(doc(), winlogbeat_event_code=4625) for _ in range(4)]
        corpus.append(dict(doc(), winlogbeat_event_code=4624))
        row = rt.fp_check_rule(rule(cond=cond), corpus)
        self.assertEqual(row["status"], "ЕСТЬ СОВПАДЕНИЯ")
        self.assertEqual(row["aggregation"]["metrics"]["card-winlogbeat_event_code"], 2)
        json.dumps(row)

    def test_single_success_no_longer_matches_composite_rules(self):
        linux = self.composite_condition(count=6, field="res")
        windows = self.composite_condition(count=5)
        linux_row = rt.fp_check_rule(rule(cond=linux), [dict(doc(), res="success")])
        windows_row = rt.fp_check_rule(rule(cond=windows), [dict(doc(), winlogbeat_event_code=4624)] * 2)
        self.assertEqual(linux_row["status"], "ЧИСТО")
        self.assertEqual(windows_row["status"], "ЧИСТО")

    def test_stats_separate_clean_and_not_applicable(self):
        stats = rt.stats_of([{"status": "ЧИСТО"}, {"status": "НЕ ПРИМЕНИМО"},
                             {"status": "ЕСТЬ СОВПАДЕНИЯ"}, {"status": "ПРОПУЩЕНО"}])
        self.assertEqual(stats["passed"], 2)
        self.assertEqual(stats["clean"], 1)
        self.assertEqual(stats["not_applicable"], 1)
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(stats["skipped"], 1)


if __name__ == "__main__":
    unittest.main()
