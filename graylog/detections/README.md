# Каталог детектов

Здесь живёт всё, что нужно, чтобы страница [docs/14-detections.md](../../docs/14-detections.md) обновлялась без ручной правки.

| Файл | Зачем |
|---|---|
| `export-catalog.js` | Скрипт для консоли браузера: читает определения событий из Graylog (только чтение) и скачивает очищенный `detections-source.json` |
| `detections-source.json` | Источник данных каталога: правила, запросы, пороги, тактики и техники. IP, MAC, отпечатки ключей и белые списки заменены на `<IP>`, `<MAC>`, `<белый список>` |
| `build_catalog.py` | Собирает из источника страницу `docs/14-detections.md` и таблицу `catalog.csv` |
| `catalog.csv` | Тот же каталог в CSV (открывается в Excel, подходит для фильтров и сводных таблиц) |

## Обновить после изменений в Graylog

1. Откройте Graylog в браузере, F12 → Console, вставьте `export-catalog.js` целиком, затем `await exportCatalog()`. Если Graylog под префиксом: `await exportCatalog({base: '/graylog'})`.
2. Скачанный `detections-source.json` положите сюда вместо старого. Просмотрите его глазами: одиночные значения вроде имён хостов скрипт не заменяет.
3. `python3 build_catalog.py` (нужен только Python 3, внешних пакетов нет).

Новое правило попадает в каталог само. Тактика и техника берутся из полей `mitre_tactic`, `mitre_technique`, `mitre_techniques` определения (их записывает `graylog/mitre/import-mitre.js`). Платформа определяется по началу названия: `Windows`, `LNX`, `macOS`, `macOS - Bi.Zone`, `KEENETIC`, `FREEIPA`/`HEALTH`, `Контейнеры`; другое начало скрипт пропустит, добавьте его в функцию `platform()`.
