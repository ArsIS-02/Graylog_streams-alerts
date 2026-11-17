#!/usr/bin/env python3
"""Проверки placeholder-aware сверки каталога с живым Graylog."""
import unittest
import rule_tester as rt


def rule(title, query="*", **overrides):
    value = {
        "title": title, "query": query, "streams": ["Logs"], "group_by": [],
        "cond": None, "priority": 2,
    }
    value.update(overrides)
    return value


class TemplateMatchTest(unittest.TestCase):
    def test_whitelist_substitution(self):
        self.assertTrue(rt.template_match(
            'field:value AND NOT ip:(<белый список>)',
            'field:value AND NOT ip:("192.168.1.10" OR "10.0.0.1")'))

    def test_real_change_is_not_hidden_by_placeholder(self):
        self.assertFalse(rt.template_match(
            'field:value AND NOT ip:(<белый список>)',
            'field:changed AND NOT ip:("192.168.1.10") AND extra:true'))

    def test_ip_domain_and_host(self):
        self.assertTrue(rt.template_match('source:<IP>', 'source:192.168.1.137'))
        self.assertTrue(rt.template_match('host:<домен>', r'host:monitoring\.test'))
        self.assertTrue(rt.template_match('Тишина: <хост>', 'Тишина: MacBook-Pro'))

    def test_shell_redirection_is_not_placeholder(self):
        query = "message:\"cat < /dev/null > /dev/tcp/<IP>/9095\""
        self.assertTrue(rt.template_match(
            query, "message:\"cat < /dev/null > /dev/tcp/192.168.1.137/9095\""))


class DiffCatalogTest(unittest.TestCase):
    def test_template_title_pairs_with_live_instance(self):
        file_rules = [rule("HEALTH - Тишина: <хост> (час)", "source:macminim2")]
        live_rules = [rule("HEALTH - Тишина: MacMiniM2 (час)", "source:macminim2")]
        self.assertEqual(rt.diff_catalog(file_rules, live_rules), [])
        expected = rt.expected_substitutions(file_rules, live_rules)
        self.assertEqual(len(expected), 1)
        self.assertEqual(expected[0]["kinds"], ["экземпляр шаблона"])

    def test_changed_property_of_template_instance_is_reported(self):
        file_rules = [rule("HEALTH - Тишина: <хост> (час)", priority=2)]
        live_rules = [rule("HEALTH - Тишина: MacMiniM2 (час)", priority=3)]
        diffs = rt.diff_catalog(file_rules, live_rules)
        self.assertEqual([row["kind"] for row in diffs], ["приоритет отличается"])

    def test_ambiguous_template_is_not_guessed(self):
        file_rules = [rule("HEALTH - Тишина: <хост> (час)")]
        live_rules = [rule("HEALTH - Тишина: host-a (час)"),
                      rule("HEALTH - Тишина: host-b (час)")]
        self.assertEqual(len(rt.diff_catalog(file_rules, live_rules)), 3)


if __name__ == "__main__":
    unittest.main()
