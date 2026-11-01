# Проверка детектов

Безопасные сценарии, которые создают события, похожие на следы атак, чтобы убедиться: правила из
[каталога детектов](../docs/14-detections.md) срабатывают. Подробно: [docs/15-detection-tests.md](../docs/15-detection-tests.md).

| Файл | Зачем |
|---|---|
| `tests_def.py` | Единый источник: id проверки, название, правила каталога, риск, условия |
| `build_tests.py` | Сверяет правила с `catalog.csv`, проверяет наличие реализации, собирает `tests.json`, встроенные описания в раннерах и страницу `docs/15-detection-tests.md` |
| `tests.json` | Собранное описание проверок (правила с полными названиями) |
| `windows/Invoke-DetectionTests.ps1` | Раннер для Windows и контроллера домена (PowerShell, UTF-8 с BOM) |
| `linux/detection-tests.sh` | Раннер для Linux с auditd |
| `macos/detection-tests.sh` | Раннер для macOS (совместим с bash 3.2) |
| `freeipa/ipa_detection_tests.py` | Раннер для FreeIPA (ipalib, Kerberos) |

```bash
sudo linux/detection-tests.sh --list                    # что проверяется
sudo linux/detection-tests.sh --id LNX-01,LNX-05 --dry-run
sudo linux/detection-tests.sh --all --yes
```

Каждый раннер пишет CSV-отчёт с колонкой `seen_in_graylog` для ручной сверки и в конце удаляет всё созданное.
Запускайте только в лаборатории.

После правки `tests_def.py` или каталога выполните `python3 build_tests.py` (нужен только Python 3).
