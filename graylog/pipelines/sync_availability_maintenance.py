#!/usr/bin/env python3
"""Безопасно добавляет HostDeck maintenance-контекст в availability Graylog.

Read-only dry run по умолчанию. Для --apply нужны GRAYLOG_URL, GRAYLOG_TOKEN,
HOSTDECK_CSV_URL (key=name&header=0), MAINTENANCE_STREAM_IDS и
MAINTENANCE_DEFINITION_IDS (через запятую). ZABBIX_DEFINITION_ID задаётся отдельно:
у aggregation-правила maintenance-поля добавляются также в group_by.

Скрипт создаёт/обновляет только ресурсы с префиксами hostdeck-maintenance-* и
availability: HostDeck maintenance / hostdeck: availability maintenance. В чужие
pipeline лишь добавляется отдельный pipeline; существующие pipeline_ids сохраняются.
Определения security не выбираются и не изменяются. Секретный URL не печатается.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
RULE_TITLE = "availability: HostDeck maintenance"
PIPELINE_TITLE = "hostdeck: availability maintenance"
MAINTENANCE_FIELDS = ("maintenance_active", "maintenance_until", "maintenance_reason")
METADATA = {"_scope", "created_at", "updated_at", "errors"}


def template(field: str) -> dict:
    return {"data_type": "string", "providers": [{
        "type": "template-v1", "template": "${source." + field + "}",
        "require_values": False, "exclude_empty_fields": True,
    }]}


def definition_update(current: dict, aggregated: bool = False) -> tuple[dict, bool]:
    """Добавляет только maintenance-поля, сохраняя маршрут и логику правила."""
    entity = {k: v for k, v in current.items() if k not in METADATA | {
        "matched_at", "scheduler"}}
    fields = dict(current.get("field_spec") or {})
    for name in MAINTENANCE_FIELDS:
        fields[name] = template(name)
    entity["field_spec"] = fields
    if aggregated:
        config = dict(current.get("config") or {})
        config["group_by"] = list(dict.fromkeys(
            list(config.get("group_by") or []) + list(MAINTENANCE_FIELDS)))
        entity["config"] = config
    comparable = {k: v for k, v in current.items() if k in entity}
    changed = any(entity[k] != comparable.get(k) for k in entity)
    return entity, changed


def merged_pipeline_ids(current: list[str], own_id: str) -> list[str]:
    return list(dict.fromkeys(list(current) + [own_id]))


def clean_entity(value: dict) -> dict:
    return {k: v for k, v in value.items() if k not in METADATA}


class Graylog:
    def __init__(self, url: str, token: str):
        self.base = url.rstrip("/") + "/api"
        self.auth = base64.b64encode((token + ":token").encode()).decode()
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def request(self, method: str, path: str, body=None, allow_404=False):
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", "Basic " + self.auth)
        req.add_header("Accept", "application/json")
        req.add_header("X-Requested-By", "hostdeck-maintenance-sync")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=45) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            if allow_404 and error.code == 404:
                return {}
            detail = error.read().decode("utf-8", "replace")[:500]
            raise RuntimeError(f"{method} {path}: HTTP {error.code}: {detail}") from error
        return json.loads(raw) if raw.strip() else {}


def ensure(api: Graylog, path: str, key: str, name: str, desired: dict,
           apply: bool, report: list) -> dict:
    response = api.request("GET", path + "?per_page=500")
    values = response if isinstance(response, list) else response.get(key, [])
    found = [item for item in values if item.get("name") == name or item.get("title") == name]
    if len(found) > 1:
        raise RuntimeError(f"Несколько ресурсов {name!r}; отказ от изменения")
    current = found[0] if found else None
    if current is None:
        report.append({"resource": name, "action": "create" if apply else "would_create"})
        return api.request("POST", path, desired) if apply else dict(desired, id="(new)")
    entity = clean_entity(current)
    changed = False
    for field, value in desired.items():
        if field == "config":
            config = dict(current.get("config") or {})
            for ck, cv in value.items():
                if config.get(ck) != cv:
                    config[ck] = cv
                    changed = True
            entity["config"] = config
        elif current.get(field) != value:
            entity[field] = value
            changed = True
    if not changed:
        report.append({"resource": name, "action": "unchanged"})
        return current
    report.append({"resource": name, "action": "update" if apply else "would_update"})
    return api.request("PUT", path + "/" + current["id"], entity) if apply else entity


def private_dump(path: Path, value) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    required = ["GRAYLOG_URL", "GRAYLOG_TOKEN", "HOSTDECK_CSV_URL",
                "MAINTENANCE_STREAM_IDS", "MAINTENANCE_DEFINITION_IDS"]
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        raise SystemExit("Нет переменных: " + ", ".join(missing))
    stream_ids = [x.strip() for x in os.environ["MAINTENANCE_STREAM_IDS"].split(",") if x.strip()]
    definition_ids = [x.strip() for x in os.environ["MAINTENANCE_DEFINITION_IDS"].split(",") if x.strip()]
    zabbix_id = os.environ.get("ZABBIX_DEFINITION_ID", "").strip()
    api = Graylog(os.environ["GRAYLOG_URL"], os.environ["GRAYLOG_TOKEN"])
    report = []
    backup = None
    if args.apply:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = Path.home() / "graylog-maintenance-backups" / stamp
        selected_ids = definition_ids + ([zabbix_id] if zabbix_id else [])
        snapshot = {
            "caches": api.request("GET", "/system/lookup/caches?per_page=500"),
            "adapters": api.request("GET", "/system/lookup/adapters?per_page=500"),
            "tables": api.request("GET", "/system/lookup/tables?per_page=500"),
            "rules": api.request("GET", "/system/pipelines/rule"),
            "pipelines": api.request("GET", "/system/pipelines/pipeline?per_page=500"),
            "connections": {sid: api.request("GET", "/system/pipelines/connections/" + sid,
                                             allow_404=True) for sid in stream_ids},
            "definitions": {rid: api.request("GET", "/events/definitions/" + rid)
                            for rid in selected_ids},
        }
        private_dump(backup / "before.json", snapshot)

    cache_body = {
        "name": "hostdeck-maintenance-cache",
        "title": "HostDeck maintenance (кэш)",
        "description": "Короткий кэш активных окон обслуживания HostDeck",
        "config": {"type": "guava_cache", "max_size": 1000,
                   "expire_after_access": 60, "expire_after_access_unit": "SECONDS",
                   "expire_after_write": 0, "expire_after_write_unit": None},
    }
    cache = ensure(api, "/system/lookup/caches", "caches",
                   "hostdeck-maintenance-cache", cache_body, args.apply, report)
    common = {"type": "dsvhttp", "url": os.environ["HOSTDECK_CSV_URL"],
              "refresh_interval": 60, "separator": ",", "line_separator": "\n",
              "quotechar": '"', "ignorechar": "#", "key_column": 0,
              "check_presence_only": False, "case_insensitive_lookup": True}
    adapters = {}
    for suffix, column, title in (("until", 9, "срок"), ("reason", 10, "причина")):
        name = f"hostdeck-maintenance-{suffix}-http"
        body = {"name": name, "title": f"HostDeck maintenance: {title} (HTTP)",
                "description": "Активное обслуживание из HostDeck CSV; секретный URL не выводится",
                "config": dict(common, value_column=column)}
        adapters[suffix] = ensure(api, "/system/lookup/adapters", "data_adapters",
                                  name, body, args.apply, report)
    for suffix, title in (("until", "срок Unix UTC"), ("reason", "причина")):
        body = {"name": f"hostdeck-maintenance-{suffix}",
                "title": f"HostDeck maintenance: {title}",
                "description": "Имя хоста → активное окно обслуживания HostDeck; истёкшее окно отдаёт until=0",
                "cache_id": cache["id"], "data_adapter_id": adapters[suffix]["id"],
                "default_single_value": "", "default_single_value_type": "NULL",
                "default_multi_value": "", "default_multi_value_type": "NULL"}
        ensure(api, "/system/lookup/tables", "lookup_tables",
               f"hostdeck-maintenance-{suffix}", body, args.apply, report)

    rule_file = HERE / "rules" / "availability-hostdeck-maintenance.rule"
    lines = rule_file.read_text(encoding="utf-8").splitlines()
    source = "\n".join(line for line in lines if not line.startswith("// description:")).strip()
    rule_body = {"title": RULE_TITLE,
                 "description": lines[0].split("// description:", 1)[1].strip(), "source": source}
    ensure(api, "/system/pipelines/rule", "rules", RULE_TITLE, rule_body, args.apply, report)

    pipelines = api.request("GET", "/system/pipelines/pipeline?per_page=500")
    pipelines = pipelines if isinstance(pipelines, list) else pipelines.get("pipelines", [])
    found = [p for p in pipelines if p.get("title") == PIPELINE_TITLE]
    if len(found) > 1:
        raise RuntimeError(f"Несколько pipeline {PIPELINE_TITLE!r}")
    desired_stages = [{"stage": 5, "match": "EITHER", "rules": [RULE_TITLE]}]
    pipeline_source = (f'pipeline "{PIPELINE_TITLE}"\n'
                       f'stage 5 match either\nrule "{RULE_TITLE}"\nend')
    if found:
        pipeline = found[0]
        if pipeline.get("stages") != desired_stages:
            report.append({"resource": PIPELINE_TITLE, "action": "update" if args.apply else "would_update"})
            entity = clean_entity(pipeline)
            entity["stages"] = desired_stages
            entity["source"] = pipeline_source
            pipeline = api.request("PUT", "/system/pipelines/pipeline/" + pipeline["id"], entity) \
                if args.apply else entity
        else:
            report.append({"resource": PIPELINE_TITLE, "action": "unchanged"})
    else:
        report.append({"resource": PIPELINE_TITLE, "action": "create" if args.apply else "would_create"})
        pipeline = api.request("POST", "/system/pipelines/pipeline", {
            "title": PIPELINE_TITLE,
            "description": "Maintenance-контекст только для явно обозначенных availability-сообщений",
            "source": pipeline_source,
            "stages": desired_stages}) if args.apply else {"id": "(new)", "stages": desired_stages}

    for stream_id in stream_ids:
        current = api.request("GET", "/system/pipelines/connections/" + stream_id,
                              allow_404=True)
        before = list(current.get("pipeline_ids") or [])
        after = merged_pipeline_ids(before, pipeline["id"])
        if before == after:
            report.append({"resource": "stream " + stream_id, "action": "unchanged"})
            continue
        report.append({"resource": "stream " + stream_id,
                       "action": "connect" if args.apply else "would_connect",
                       "preserved_pipelines": len(before)})
        if args.apply:
            api.request("POST", "/system/pipelines/connections/to_stream",
                        {"stream_id": stream_id, "pipeline_ids": after})

    selected = [(rule_id, False) for rule_id in definition_ids]
    if zabbix_id:
        selected.append((zabbix_id, True))
    for rule_id, aggregated in selected:
        current = api.request("GET", "/events/definitions/" + rule_id)
        entity, changed = definition_update(current, aggregated)
        if not changed:
            report.append({"resource": "definition " + rule_id, "action": "unchanged"})
            continue
        report.append({"resource": "definition " + rule_id,
                       "action": "update" if args.apply else "would_update",
                       "title": current.get("title")})
        if args.apply:
            api.request("PUT", "/events/definitions/" + rule_id, entity)
            verify = api.request("GET", "/events/definitions/" + rule_id)
            assert verify.get("notifications") == current.get("notifications")
            assert verify.get("priority") == current.get("priority")
            assert verify.get("state") == current.get("state")
            assert verify.get("key_spec") == current.get("key_spec")
            assert verify["config"].get("query") == current["config"].get("query")
            assert set(MAINTENANCE_FIELDS).issubset(set(verify.get("field_spec") or {}))

    result = {"mode": "apply" if args.apply else "dry-run", "changes": report}
    if args.apply:
        private_dump(backup / "result.json", result)
        result["backup"] = str(backup)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
