#!/usr/bin/env python3
"""Еженедельный read-only аудит Graylog и итогов закрытия алертов IRIS.

Запускает существующие ``drift`` и ``fp-check`` Rule Tester, собирает закрытые
алерты IRIS, сохраняет обезличенную сводку и обновляет одну страницу HomeWiki.
Не изменяет правила Graylog, алерты IRIS или расписание основного Rule Tester.
"""
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
WIKI_PAGE = "art-graylog-quality-weekly"
WIKI_TITLE = "Graylog/IRIS - Еженедельный аудит качества правил"
RESOLUTIONS = {
    1: "False Positive",
    2: "True Positive With Impact",
    3: "True Positive Without Impact",
    4: "Not Applicable",
    5: "Unknown",
    6: "Legitimate",
}


def read_env(path):
    values = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values[key] = value
    except FileNotFoundError:
        pass
    return values


def iso(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    # IRIS возвращает timestamps без смещения в UTC; для окна используем aware datetime.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone()


def rule_name(title):
    """Убрать изменчивый суффикс агрегации, сохранив название правила."""
    title = title or "(без названия)"
    return re.sub(r"\s*:\s*[^:]*?\s+-\s+[a-z_]+\(\)=.*$", "", title).strip()


def md_cell(value):
    return str(value).replace("|", "/").replace("\n", " ")


def run_command(command, log_path, env):
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as log:
        proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                              env=env, timeout=1800, check=False)
    print("%s: код %d, журнал %s" % (Path(command[-1]).name, proc.returncode, log_path), flush=True)
    return proc.returncode


def latest_report(report_dir, kind, before):
    candidates = [p for p in report_dir.glob("*-" + kind + ".json") if p not in before]
    if not candidates:
        raise RuntimeError("Rule Tester не создал отчёт " + kind)
    return max(candidates, key=lambda p: p.stat().st_mtime)


def sanitized_tool_report(path, returncode):
    raw = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for row in raw.get("rows", []):
        if row.get("status") in ("РАСХОЖДЕНИЕ", "ЕСТЬ СОВПАДЕНИЯ", "ПРОПУЩЕНО", "НЕ ПРИМЕНИМО"):
            rows.append({"rule": row.get("rule"), "status": row.get("status"),
                         "detail": row.get("detail"), "priority": row.get("priority"),
                         "kind": row.get("kind")})
    return {
        "returncode": returncode,
        "summary": raw.get("summary"),
        "stats": raw.get("stats") or {},
        "meta": raw.get("meta") or {},
        "version": raw.get("version"),
        "report_json": str(path),
        "findings": rows,
    }


def iris_client(env):
    base = env["TB_IRIS_URL"].rstrip("/")
    key = env["TB_IRIS_KEY"]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def get(path, params):
        url = base + path + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + key})
        with urllib.request.urlopen(req, context=ctx, timeout=45) as response:
            return json.loads(response.read().decode() or "{}")

    return get


def collect_iris(env, days):
    get = iris_client(env)
    now = datetime.now().astimezone()
    cutoff = now - timedelta(days=days)
    rows = []
    page = 1
    total = None
    while True:
        payload = get("/api/v2/alerts", {
            "alert_status_id": 6, "per_page": 200, "page": page, "sort": "desc",
        })
        batch = payload.get("data") or []
        total = payload.get("total", total)
        rows.extend(batch)
        if not batch or len(batch) < 200 or (total is not None and len(rows) >= total):
            break
        page += 1
        if page > 100:
            raise RuntimeError("Слишком много страниц закрытых алертов IRIS")

    selected = []
    fallback = 0
    for row in rows:
        closed = iso(row.get("resolved_at"))
        time_field = "resolved_at"
        if closed is None:
            closed = iso(row.get("date_update"))
            time_field = "date_update"
        if closed is None or closed < cutoff:
            continue
        fallback += int(time_field == "date_update")
        resolution_id = row.get("alert_resolution_status_id")
        resolution = (row.get("resolution_status") or {}).get("resolution_status_name")
        if not resolution:
            resolution = RESOLUTIONS.get(resolution_id, "Без разрешения" if resolution_id is None else "Неизвестно")
        selected.append({
            "id": row.get("alert_id"),
            "title": row.get("alert_title"),
            "rule": rule_name(row.get("alert_title")),
            "resolution_id": resolution_id,
            "resolution": resolution,
            "closed_at": closed.isoformat(timespec="seconds"),
            "time_field": time_field,
        })
    selected.sort(key=lambda item: item["closed_at"], reverse=True)
    resolution_counts = Counter(item["resolution"] for item in selected)
    rule_counts = Counter(item["rule"] for item in selected)
    return {
        "days": days,
        "from": cutoff.isoformat(timespec="seconds"),
        "to": now.isoformat(timespec="seconds"),
        "closed_total_api": total if total is not None else len(rows),
        "closed_in_period": len(selected),
        "date_update_fallback": fallback,
        "resolutions": [{"name": name, "count": count}
                        for name, count in sorted(resolution_counts.items(), key=lambda x: (-x[1], x[0]))],
        "rules": [{"rule": name, "count": count}
                  for name, count in sorted(rule_counts.items(), key=lambda x: (-x[1], x[0]))],
        "alerts": selected,
    }


def drift_counts(summary):
    match = re.search(
        r"правил в каталоге (\d+), в Graylog (\d+), расхождений (\d+)"
        r"(?:, ожидаемых подстановок (\d+))?", summary or "")
    if not match:
        return {}
    return {"catalog": int(match.group(1)), "graylog": int(match.group(2)),
            "differences": int(match.group(3)),
            "expected": int(match.group(4) or 0)}


def render_markdown(report):
    drift = report["drift"]
    fp = report["fp_check"]
    iris = report["iris"]
    dc = drift_counts(drift.get("summary"))
    stats = fp.get("stats") or {}
    meta = fp.get("meta") or {}
    lines = [
        "Автоматический еженедельный аудит качества детектов. Обновлено: **%s**." % report["finished"],
        "",
        "> Проверки только читают Graylog и IRIS. Совпадения `fp-check` — кандидаты для ручного разбора,",
        "> а не автоматически доказанные ложные срабатывания. Правила и алерты этим заданием не изменяются.",
        "",
        "## Сводка",
        "",
        "| Проверка | Результат |",
        "|---|---|",
        "| Версия каталога | `%s` |" % report["git"]["commit"],
        "| Drift: каталог ↔ Graylog | правил в каталоге: %s; в Graylog: %s; расхождений: **%s**; ожидаемых подстановок: %s |" % (
            dc.get("catalog", "?"), dc.get("graylog", "?"), dc.get("differences", "?"), dc.get("expected", "?")),
        "| FP-check | правил: %s; чисто: %s; с совпадениями: **%s**; не применимо: %s; пропущено: %s |" % (
            stats.get("total", "?"), stats.get("clean", stats.get("passed", "?")), stats.get("failed", "?"),
            stats.get("not_applicable", 0), stats.get("skipped", "?")),
        "| Корпус FP-check | %s сообщений за %s (лимит %s) |" % (
            meta.get("corpus", "?"), meta.get("since", "?"), report["parameters"]["limit"]),
        "| Закрыто алертов IRIS | **%d** за %d суток |" % (iris["closed_in_period"], iris["days"]),
        "",
        "## 1. Расхождения каталога и Graylog",
        "",
    ]
    drift_findings = [r for r in drift.get("findings", []) if r.get("status") == "РАСХОЖДЕНИЕ"]
    if not drift_findings:
        lines.append("Расхождений не найдено.")
    else:
        lines.extend(["| Правило | Расхождение |", "|---|---|"])
        for row in drift_findings[:40]:
            lines.append("| %s | %s |" % (md_cell(row.get("rule")), md_cell(row.get("detail"))))
        if len(drift_findings) > 40:
            lines.append("\nПоказаны 40 из %d; полный список — в JSON на сервере." % len(drift_findings))

    lines.extend(["", "## 2. Кандидаты на ложные срабатывания", ""])
    fp_findings = [r for r in fp.get("findings", []) if r.get("status") == "ЕСТЬ СОВПАДЕНИЯ"]
    if not fp_findings:
        lines.append("Совпадений в полученном корпусе не найдено.")
    else:
        lines.extend(["| Правило | Совпадения в корпусе |", "|---|---|"])
        for row in fp_findings[:40]:
            lines.append("| %s | %s |" % (md_cell(row.get("rule")), md_cell(row.get("detail"))))
        if len(fp_findings) > 40:
            lines.append("\nПоказаны 40 из %d; полный список — в JSON на сервере." % len(fp_findings))
    not_applicable = [r for r in fp.get("findings", []) if r.get("status") == "НЕ ПРИМЕНИМО"]
    if not_applicable:
        lines.extend(["", "Не применимо к проверке отдельных сообщений: **%d**. Правила тишины срабатывают "
                      "при отсутствии событий, поэтому обычные совпадения их запросов не считаются FP." % len(not_applicable)])
        review = [r for r in not_applicable if r.get("kind") != "тишина"]
        for row in review[:20]:
            lines.append("- **%s** — %s" % (row.get("rule"), row.get("detail")))
    skipped = [r for r in fp.get("findings", []) if r.get("status") == "ПРОПУЩЕНО"]
    if skipped:
        lines.extend(["", "Пропущенные запросы требуют отдельной проверки:", ""])
        for row in skipped[:20]:
            lines.append("- **%s** — %s" % (row.get("rule"), row.get("detail")))

    lines.extend(["", "## 3. Итоги закрытия алертов IRIS", ""])
    if not iris["resolutions"]:
        lines.append("За выбранный период закрытых алертов не найдено.")
    else:
        lines.extend(["| Разрешение | Количество |", "|---|---:|"])
        for row in iris["resolutions"]:
            lines.append("| %s | %d |" % (row["name"], row["count"]))
        lines.extend(["", "### Наиболее частые правила среди закрытых", "",
                      "| Правило | Количество |", "|---|---:|"])
        for row in iris["rules"][:20]:
            lines.append("| %s | %d |" % (md_cell(row["rule"]), row["count"]))
    lines.extend([
        "",
        "Всего закрытых записей доступно через API: %s. Для %d записей в выборке `resolved_at` пуст, "
        "поэтому использовано `date_update` (время последнего изменения)." % (
            iris["closed_total_api"], iris["date_update_fallback"]),
        "",
        "## Ограничения и эксплуатация",
        "",
        "- FP-check поддерживает числовые диапазоны Lucene. Для агрегаций учитывает порог, `group_by` и скользящее окно; точное расписание выполнения Graylog не воспроизводится.",
        "- Правила тишины не оцениваются по отдельным совпадениям: их условие относится к отсутствию событий.",
        "- Корпус ограничен лимитом и не является гарантированно «чистым»: совпадение может быть настоящим инцидентом.",
        "- Сырые сообщения Graylog, описания алертов и секреты в эту сводку не включаются.",
        "- Исторические отчёты: `%s`; технические журналы: `%s`." % (
            report["paths"]["history_dir"], report["paths"]["logs_dir"]),
        "- Исходный отчёт Rule Tester: `%s`." % fp.get("report_json"),
        "",
        "Расписание: понедельник, 09:17 YEKT, пользовательский cron на redos-server.",
    ])
    if report["errors"]:
        lines.extend(["", "## Технические ошибки", ""] +
                     ["- " + error for error in report["errors"]])
    return "\n".join(lines) + "\n"


def update_wiki(db_path, body, now_ts):
    db = sqlite3.connect(db_path)
    try:
        db.execute(
            """INSERT INTO pages(id,title,category,body,priority,query,streams,tactics,techniques,examples,source,type,link,ord,edited,created,updated)
               VALUES(?,?,?,?,2,'','[]','[]','[]','[]','custom','article','',60,1,?,?)
               ON CONFLICT(id) DO UPDATE SET title=excluded.title, body=excluded.body, updated=excluded.updated""",
            (WIKI_PAGE, WIKI_TITLE, "Инструменты / Graylog", body, now_ts, now_ts),
        )
        db.commit()
        row = db.execute("SELECT id,title FROM pages WHERE id=?", (WIKI_PAGE,)).fetchone()
        if not row:
            raise RuntimeError("Страница HomeWiki после сохранения не найдена")
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=str(HERE / "repo"), help="отдельный чистый clone репозитория")
    parser.add_argument("--data", default=os.environ.get("RT_DATA", str(HERE / "data")))
    parser.add_argument("--since", default="7d", help="окно FP-check: 24h, 7d и т.п.")
    parser.add_argument("--limit", type=int, default=2000)
    parser.add_argument("--iris-days", type=int, default=7)
    parser.add_argument("--skip-pull", action="store_true", help="диагностика: не обновлять clone")
    parser.add_argument("--wiki-db", default="/home/redos/homewiki/data/homewiki.db")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    data = Path(args.data).resolve()
    history = data / "quality"
    logs = data / "logs"
    history.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    started_dt = datetime.now().astimezone()
    stamp = started_dt.strftime("%Y%m%d-%H%M%S")
    errors = []

    env = os.environ.copy()
    for path in ("/home/redos/rule-tester/rule-tester.env",
                 "/home/redos/ticketbridge/ticketbridge.env"):
        for key, value in read_env(path).items():
            env.setdefault(key, value)
    env["RT_DATA"] = str(data)
    env["GRAYLOG_URL"] = "http://127.0.0.1:9000"
    # Токен старого rule-tester.env может быть отозван; TicketBridge использует рабочий read token.
    if env.get("TB_GRAYLOG_TOKEN"):
        env["GRAYLOG_TOKEN"] = env["TB_GRAYLOG_TOKEN"]
    missing = [key for key in ("GRAYLOG_TOKEN", "TB_IRIS_URL", "TB_IRIS_KEY") if not env.get(key)]
    if missing:
        raise SystemExit("Не заполнены переменные окружения: " + ", ".join(missing))

    if not args.skip_pull:
        pull_log = logs / (stamp + "-git-pull.log")
        rc = run_command(["git", "-C", str(repo), "pull", "--ff-only"], pull_log, env)
        if rc != 0:
            raise RuntimeError("git pull --ff-only завершился ошибкой; см. %s" % pull_log)
    commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
                                     text=True, env=env).strip()
    tester = repo / "rule-tester" / "rule_tester.py"
    common = [sys.executable, str(tester), "--url", env["GRAYLOG_URL"], "--source", "live"]

    results = {}
    for kind, suffix in (("drift", ["drift"]), ("fp_check", ["fp-check", "--since", args.since, "--limit", str(args.limit)])):
        report_dir = data / "reports"
        before = set(report_dir.glob("*.json"))
        rc = run_command(common + suffix, logs / (stamp + "-" + kind + ".log"), env)
        try:
            path = latest_report(report_dir, "drift" if kind == "drift" else "fp", before)
            results[kind] = sanitized_tool_report(path, rc)
        except Exception as exc:
            results[kind] = {"returncode": rc, "summary": "", "stats": {}, "meta": {}, "findings": []}
            errors.append("%s: %s" % (kind, exc))
        if rc not in (0, 1):
            errors.append("%s завершился технической ошибкой, код %d" % (kind, rc))

    iris = collect_iris(env, args.iris_days)
    finished_dt = datetime.now().astimezone()
    report = {
        "schema_version": 1,
        "run": "quality-" + stamp,
        "started": started_dt.isoformat(timespec="seconds"),
        "finished": finished_dt.isoformat(timespec="seconds"),
        "status": "partial" if errors else "ok",
        "parameters": {"since": args.since, "limit": args.limit, "iris_days": args.iris_days},
        "git": {"repo": str(repo), "commit": commit},
        "drift": results["drift"],
        "fp_check": results["fp_check"],
        "iris": iris,
        "errors": errors,
        "paths": {"history_dir": str(history), "logs_dir": str(logs)},
    }
    markdown = render_markdown(report)
    json_path = history / (stamp + ".json")
    md_path = history / (stamp + ".md")
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(markdown, encoding="utf-8")
    (data / "latest.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (data / "latest.md").write_text(markdown, encoding="utf-8")
    update_wiki(args.wiki_db, markdown, time.time())
    print("Отчёт: %s" % md_path)
    print("Wiki: https://homewiki.apps.monitoring.test/rules/%s" % WIKI_PAGE)
    print("Статус: %s" % report["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
