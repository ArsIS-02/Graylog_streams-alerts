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


def coverage(rules, meta, sample_counts, live, art_titles=None, method_titles=None):
    """Тактики → техники → правила; правила без ручных образцов; правила без срабатываний;
    матрица покрытия тестами (ручные/настоящие образцы, Atomic Red Team, методика главы 15) —
    чтобы дыры вроде Контейнеров и Keenetic (вообще без тестов) было видно одним списком,
    а не приходилось сверять три источника в голове."""
    art_titles = art_titles or set()
    method_titles = method_titles or set()
    tactics = {}
    for r in rules:
        m = meta.get(r["title"], {"tactic": "—", "technique": "", "techniques": []})
        t = tactics.setdefault(m["tactic"] if m["tactic"] != "—" else "Без тактики (служебные правила)",
                               {"techniques": {}, "rules": 0})
        t["rules"] += 1
        for tid in (m["techniques"] or ["без техники"]):
            t["techniques"].setdefault(tid, []).append(r["title"])
    active = [r for r in rules if r["kind"] != "тишина"]
    no_manual = [r["title"] for r in active if not sample_counts.get(r["title"], {}).get("manual")]
    no_art = [r["title"] for r in active if r["title"] not in art_titles]
    no_method = [r["title"] for r in active if r["title"] not in method_titles]
    uncovered = [r["title"] for r in active if r["title"] not in art_titles and r["title"] not in method_titles
                 and not sample_counts.get(r["title"], {}).get("manual")]
    quiet = []
    quiet_last = {}
    if live:
        for r in rules:
            if r["kind"] != "тишина" and live.get(r["title"], {}).get("d30") == 0:
                quiet.append(r["title"])
                quiet_last[r["title"]] = (live.get(r["title"]) or {}).get("last")
    out = [{"tactic": k, "rules": v["rules"],
            "techniques": [{"id": tid, "rules": ts} for tid, ts in sorted(v["techniques"].items())]}
           for k, v in sorted(tactics.items(), key=lambda kv: -kv[1]["rules"])]
    return {"tactics": out, "no_manual": no_manual, "no_art": no_art, "no_method": no_method,
            "uncovered": uncovered, "quiet": quiet, "quiet_last": quiet_last, "total": len(rules),
            "with_manual": len(rules) - len(no_manual),
            "with_art": len(active) - len(no_art), "with_method": len(active) - len(no_method)}


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
