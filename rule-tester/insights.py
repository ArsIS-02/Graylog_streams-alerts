"""Покрытие и качество: сводки по правилам без обращения к Graylog (кроме готовых счётчиков)."""
import json
import re

import lucene as L


def catalog_meta(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))["definitions"]
    except (OSError, ValueError, KeyError):
        return {}
    return {d["title"]: {"tactic": d.get("tactic") or "—", "technique": d.get("technique") or "",
                         "techniques": [t.strip() for t in (d.get("techniques") or "").split(",") if t.strip()]}
            for d in data}


def coverage(rules, meta, sample_counts, live):
    """Тактики → техники → правила; правила без ручных образцов; правила без срабатываний."""
    tactics = {}
    for r in rules:
        m = meta.get(r["title"], {"tactic": "—", "technique": "", "techniques": []})
        t = tactics.setdefault(m["tactic"] if m["tactic"] != "—" else "Без тактики (служебные правила)",
                               {"techniques": {}, "rules": 0})
        t["rules"] += 1
        for tid in (m["techniques"] or ["без техники"]):
            t["techniques"].setdefault(tid, []).append(r["title"])
    no_manual = [r["title"] for r in rules if not sample_counts.get(r["title"], {}).get("manual")
                 and r["kind"] != "тишина"]
    quiet = []
    if live:
        quiet = [r["title"] for r in rules if r["kind"] != "тишина" and live.get(r["title"], {}).get("d30") == 0]
    out = [{"tactic": k, "rules": v["rules"],
            "techniques": [{"id": tid, "rules": ts} for tid, ts in sorted(v["techniques"].items())]}
           for k, v in sorted(tactics.items(), key=lambda kv: -kv[1]["rules"])]
    return {"tactics": out, "no_manual": no_manual, "quiet": quiet,
            "total": len(rules), "with_manual": len(rules) - len(no_manual)}


def quality(rules, first_pos_docs):
    """Список замечаний: {severity, kind, rule, text}."""
    issues, by_q, nodes = [], {}, {}
    for r in rules:
        for f in r["flags"]:
            sev = "warn" if "Lucene" in f or "заглушка" in f or "отличается" in f else "info"
            kind = ("заглушка" if "заглушка" in f else "отличие от каталога" if "отличается" in f
                    else "регулярка Lucene" if "Lucene" in f else "запрос")
            issues.append({"severity": sev, "kind": kind, "rule": r["title"], "text": f})
        q = re.sub(r"\s+", " ", r["query"].strip())
        if q not in ("*", ""):
            by_q.setdefault(q, []).append(r["title"])
        if "заглушка" not in " ".join(r["flags"]) and r["query"].strip() not in ("*", "") and r["kind"] != "тишина":
            try:
                nodes[r["title"]] = L.parse(r["query"])[0]
            except L.QueryError:
                issues.append({"severity": "bad", "kind": "запрос не разобран", "rule": r["title"],
                               "text": "запрос не разбирается тестером"})
    for q, titles in by_q.items():
        if len(titles) > 1:
            for t in titles:
                issues.append({"severity": "info", "kind": "одинаковый запрос", "rule": t,
                               "text": "тот же запрос у: " + "; ".join(x for x in titles if x != t)[:200]})
    for title, doc in first_pos_docs.items():
        others = [t for t, n in nodes.items() if t != title and L.evaluate(n, doc)]
        if others:
            issues.append({"severity": "info", "kind": "перекрытие", "rule": title,
                           "text": "образец правила находят ещё: " + "; ".join(o for o in others[:4])})
    return issues
