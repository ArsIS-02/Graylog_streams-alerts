import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parent.parent / "graylog" / "pipelines" / "sync_availability_maintenance.py"
SPEC = importlib.util.spec_from_file_location("sync_availability_maintenance", MODULE)
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)


class AvailabilityMaintenanceTest(unittest.TestCase):
    def definition(self):
        return {
            "id": "availability-1", "title": "Availability", "state": "ENABLED",
            "priority": 2, "alert": True, "key_spec": ["event"],
            "notifications": [{"notification_id": "mail"}, {"notification_id": "iris"}],
            "config": {"query": "zabbix_event_status:PROBLEM", "group_by": ["zabbix_event_id"]},
            "field_spec": {"host": {"data_type": "string", "providers": []}},
            "_scope": "DEFAULT", "matched_at": None, "scheduler": None,
        }

    def test_definition_preserves_detection_and_notifications(self):
        current = self.definition()
        original_notifications = current["notifications"].copy()
        entity, changed = sync.definition_update(current, aggregated=True)
        self.assertTrue(changed)
        self.assertEqual(entity["notifications"], original_notifications)
        self.assertEqual(entity["priority"], 2)
        self.assertEqual(entity["state"], "ENABLED")
        self.assertEqual(entity["key_spec"], ["event"])
        self.assertEqual(entity["config"]["query"], "zabbix_event_status:PROBLEM")
        self.assertEqual(entity["config"]["group_by"], [
            "zabbix_event_id", "maintenance_active", "maintenance_until", "maintenance_reason"])
        self.assertEqual(set(sync.MAINTENANCE_FIELDS), set(entity["field_spec"]) - {"host"})
        self.assertNotIn("_scope", entity)

    def test_definition_update_is_idempotent(self):
        first, _ = sync.definition_update(self.definition(), aggregated=True)
        second, changed = sync.definition_update(first, aggregated=True)
        self.assertFalse(changed)
        self.assertEqual(first, second)

    def test_non_aggregation_does_not_change_grouping(self):
        current = self.definition()
        entity, _ = sync.definition_update(current, aggregated=False)
        self.assertEqual(entity["config"]["group_by"], ["zabbix_event_id"])

    def test_pipeline_connection_preserves_existing_ids(self):
        self.assertEqual(sync.merged_pipeline_ids(["security", "inventory"], "maintenance"),
                         ["security", "inventory", "maintenance"])
        self.assertEqual(sync.merged_pipeline_ids(["security", "maintenance"], "maintenance"),
                         ["security", "maintenance"])

    def test_rule_is_limited_to_availability_signals(self):
        rule = (MODULE.parent / "rules" / "availability-hostdeck-maintenance.rule").read_text()
        for signal in ("zabbix_event_status", "hd_event", "hr_event", "Cannot contact any KDC"):
            self.assertIn(signal, rule)
        self.assertIn("to_long(lookup_value", rule)
        self.assertIn('to_string($message.hr_agent_name)', rule)
        self.assertNotIn("drop_message", rule)
        self.assertNotIn("route_to_stream", rule)


if __name__ == "__main__":
    unittest.main()
