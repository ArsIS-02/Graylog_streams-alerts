#!/usr/bin/env python3
"""Собирает rules.json из файлов rules/*.rule.

Первая строка файла вида `// description: ...` становится описанием правила в Graylog и
в источник правила не попадает. Название берётся из строки `rule "..."`.

Запуск (из каталога graylog/pipelines):  python3 build_rules_json.py
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DESC_RE = re.compile(r"^//\s*description:\s*(.*)$")
TITLE_RE = re.compile(r'^rule\s+"([^"]+)"\s*$', re.M)


def parse(path: Path) -> dict:
    lines = path.read_text(encoding="utf-8").splitlines()
    description = ""
    body = []
    for line in lines:
        m = DESC_RE.match(line)
        if m and not body:
            description = m.group(1).strip()
            continue
        body.append(line)
    source = "\n".join(body).strip()
    m = TITLE_RE.search(source)
    if not m:
        sys.exit(f"{path.name}: не найдена строка rule \"...\"")
    return {"title": m.group(1), "description": description, "source": source}


def main() -> None:
    files = sorted((HERE / "rules").glob("*.rule"))
    if not files:
        sys.exit("нет файлов rules/*.rule")
    spec = [parse(f) for f in files]
    titles = [r["title"] for r in spec]
    if len(titles) != len(set(titles)):
        sys.exit("повторяющиеся названия правил")
    out = HERE / "rules.json"
    out.write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{out.name}: {len(spec)} правил")


if __name__ == "__main__":
    main()
