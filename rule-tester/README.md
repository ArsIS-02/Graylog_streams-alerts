# rule-tester

Проверка правил Graylog без запуска чего-либо на хостах: на сервер Graylog отправляются готовые сообщения (GELF HTTP), затем проверяется, находят ли их запросы правил и появляются ли события. Подробно: [docs/16-rule-tester.md](../docs/16-rule-tester.md).

| Файл | Зачем |
|---|---|
| `rule_tester.py` | Консольный инструмент: `selftest`, `list`, `generate`, `doctor`, `setup`, `harvest`, `run-queries`, `run-e2e` |
| `lucene.py` | Разбор запросов Lucene, вычислитель, сборка образцов, замечания к регулярным выражениям |
| `graylog_api.py` | REST Graylog (чтение) и GELF HTTP |
| `web.py`, `web_index.html` | Веб-интерфейс (правила, запуск, результаты), расписание |
| `mock_graylog.py` | Заглушка Graylog для проверки самого инструмента |
| `samples/manual.json` | Ручные образцы (положительные и отрицательные) |
| `Containerfile`, `deploy/` | Контейнер Podman, compose, quadlet, пример настроек |

Нужен только Python 3.11+. Токен API читается из переменной `GRAYLOG_TOKEN`.

```bash
python3 rule_tester.py selftest        # офлайн, Graylog не нужен
```
