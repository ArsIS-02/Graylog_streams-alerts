#!/usr/bin/env python3
"""Утренний дайджест экосистемы homelab → Graylog (GELF) → письмо.

Один раз в день (systemd-timer) собирает за последние 24 часа:
  - пульсы своих инструментов (hr/hd/zs/tl _event:heartbeat): сколько пришло,
    когда последний, какие счётчики он нёс (молчащие агенты, провалы проверок…);
  - срабатывания алертов (поток All events), сгруппированные по правилам.

Результат — одно GELF-сообщение dg_event=digest на вход «Homelab tools».
Правило «DIGEST - Утренний дайджест экосистемы» в Graylog ловит его и шлёт
письмо уведомлением «Mail.ru Daily Digest». Почтовых кредов в скрипте нет —
отправкой занимается сам Graylog.

Запуск вручную:  python3 morning-digest.py [--dry-run]
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timedelta, timezone

GRAYLOG = os.environ.get("DIGEST_GRAYLOG_URL", "https://graylog.apps.monitoring.test")
GRAYLOG_AUTH = (os.environ.get("DIGEST_GRAYLOG_USER", "admin"),
                os.environ.get("DIGEST_GRAYLOG_PASSWORD", "admin"))
GELF_TARGET = (os.environ.get("DIGEST_GELF_HOST", "127.0.0.1"),
               int(os.environ.get("DIGEST_GELF_PORT", "12206")))
TZ = timezone(timedelta(hours=5), name="YEKT")   # Asia/Yekaterinburg
RANGE_S = 24 * 3600
ALL_EVENTS_STREAM = "000000000000000000000002"

# (название, запрос пульса, [(поле, подпись)], норма пульсов в сутки)
TOOLS = [
    ("HomeRepo",   "hr_event:heartbeat", [("hr_hosts_total", "устройств"), ("hr_hosts_silent", "молчат")], 20),
    ("HostDeck",   "hd_event:heartbeat", [("hd_hosts_total", "хостов"), ("hd_checks_failing", "провалов")], 20),
    ("ZaSlon",     "zs_event:heartbeat", [("zs_hosts_total", "хостов")], 20),
    ("TrafficLens", "tl_event:heartbeat", [("tl_jobs_total", "задач"), ("tl_iocs_total", "IOC")], 20),
]

CHUNK = 8000
MAX_CHUNKS = 128


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def search_csv(query: str, fields: list[str], range_s: int = RANGE_S,
               limit: int = 500, stream: str | None = None) -> list[dict]:
    """Универсальный поиск Graylog (CSV-выгрузка) → список строк-словарей."""
    params = {"query": query, "range": str(range_s), "limit": str(limit),
              "fields": ",".join(fields)}
    if stream:
        params["filter"] = f"streams:{stream}"
    url = f"{GRAYLOG}/api/search/universal/relative?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Basic " + base64.b64encode(
        f"{GRAYLOG_AUTH[0]}:{GRAYLOG_AUTH[1]}".encode()).decode())
    with urllib.request.urlopen(req, context=_ctx(), timeout=30) as r:
        text = r.read().decode("utf-8", "replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return []
    import csv
    import io
    return list(csv.DictReader(io.StringIO(text)))


def local(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(TZ)


def collect_pulses() -> tuple[list[str], list[str]]:
    """Строки дайджеста по пульсам + список молчащих инструментов."""
    lines, silent = [], []
    now = datetime.now(TZ)
    for name, query, counters, norm in TOOLS:
        try:
            rows = search_csv(query, ["timestamp", "message"] + [f for f, _ in counters])
        except Exception as e:  # noqa: BLE001 — дайджест должен выйти даже при сбое
            lines.append(f"❓ {name}: поиск не удался ({e})")
            silent.append(name)
            continue
        if not rows:
            lines.append(f"❌ {name}: пульсов за сутки нет")
            silent.append(name)
            continue
        last = max(rows, key=lambda r: r["timestamp"])
        last_dt = local(last["timestamp"])
        age_h = (now - last_dt).total_seconds() / 3600
        cnt = ", ".join(f"{label} {last[f]}" for f, label in counters if last.get(f))
        ok = age_h < 2                      # живость — по свежести последнего пульса
        if not ok:
            silent.append(name)
        gaps = "" if len(rows) >= norm else f", пропуски за сутки ({len(rows)}/{norm}+)"
        lines.append(f"{'✅' if ok else '❌'} {name}: {len(rows)} пульс(ов), последний {last_dt:%H:%M}"
                     + (f" ({cnt})" if cnt else "") + gaps
                     + ("" if ok else f" — {age_h:.0f} ч назад!"))
    return lines, silent


COUNT_TAIL = re.compile(r"\s*[-:]\s*count\(\)=[\d.]+$")


def collect_alerts() -> tuple[list[str], int]:
    """Строки дайджеста по алертам + их число."""
    try:
        rows = search_csv("*", ["timestamp", "message"], stream=ALL_EVENTS_STREAM)
    except Exception as e:  # noqa: BLE001
        return [f"❓ Алерты: поиск не удался ({e})"], 0
    by_rule: dict[str, int] = {}
    for r in rows:
        title = COUNT_TAIL.sub("", r["message"])   # «— count()=1.0» в хвосте события
        by_rule[title] = by_rule.get(title, 0) + 1
    if not by_rule:
        return ["срабатываний нет 🎉"], 0
    lines = [f"{n}× {title}" for title, n in
             sorted(by_rule.items(), key=lambda kv: -kv[1])]
    return lines, sum(by_rule.values())


def gelf_send(short: str, fields: dict) -> None:
    msg = {"version": "1.1", "host": socket.gethostname(), "short_message": short,
           "timestamp": time.time(), "level": 6}
    for k, v in fields.items():
        msg["_" + k] = v
    data = zlib.compress(json.dumps(msg, ensure_ascii=False).encode())
    if len(data) <= CHUNK:
        packets = [data]
    else:
        parts = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)]
        if len(parts) > MAX_CHUNKS:
            raise ValueError("дайджест слишком большой для GELF")
        mid = os.urandom(8)
        packets = [b"\x1e\x0f" + mid + struct.pack("BB", n, len(parts)) + p
                   for n, p in enumerate(parts)]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for p in packets:
            sock.sendto(p, GELF_TARGET)
    finally:
        sock.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Утренний дайджест экосистемы → GELF")
    ap.add_argument("--dry-run", action="store_true", help="только показать текст, не отправлять")
    args = ap.parse_args()

    now = datetime.now(TZ)
    pulse_lines, silent = collect_pulses()
    alert_lines, alerts_total = collect_alerts()

    status = "всё в норме" if not silent else "молчат: " + ", ".join(silent)
    digest = (f"📨 Утренний дайджест экосистемы · {now:%d.%m.%Y %H:%M} (YEKT)\n"
              f"\n💓 Пульсы за сутки:\n" + "\n".join(pulse_lines) +
              f"\n\n🚨 Алерты за сутки ({alerts_total}):\n" + "\n".join(alert_lines) +
              f"\n\nИтог: {status}\n"
              f"Дашборд: https://graylog.apps.monitoring.test/dashboards\n")

    if args.dry_run:
        print(digest)
        return 0
    gelf_send(digest, {"dg_event": "digest", "homelab_app": "digest",
                       "dg_status": status, "dg_alerts_total": alerts_total,
                       "dg_silent_tools": ", ".join(silent)})
    print(f"отправлено: {len(digest)} символов, статус «{status}»", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
