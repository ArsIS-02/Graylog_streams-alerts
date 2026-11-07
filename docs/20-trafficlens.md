# 20. TrafficLens: анализ трафика и база IOC в Graylog

[TrafficLens](https://github.com/ArsIS-02/TrafficLens) разбирает записи сетевого трафика (Zeek, Suricata, свои и открытые базы IOC) и выносит итог: «Компрометация», «Подозрительно» или «Чисто». Эта глава связывает его с Graylog в обе стороны:

- **TrafficLens → Graylog.** Итоги анализа, совпадения с IOC и находки ретропроверки приходят по GELF в отдельный поток. По ним срабатывают алерты и уходят письма, как для остальных источников.
- **Graylog ← TrafficLens.** База IOC TrafficLens, которая каждый день пополняется из abuse.ch, C2IntelFeeds, Threatview, Spamhaus и других списков, подключается как Lookup Table. Pipeline сверяет с ней адреса из логов: баны Keenetic, входы в Linux и Windows. Так IOC работают не только для трафика, который прошёл через TrafficLens.

> **Статус проверки.** Отправка GELF и выгрузка CSV проверены тестами TrafficLens: локальный UDP-приёмник собирает сообщения и их части. Определения событий, правила pipeline и таблица `trafficlens-iocs` подготовлены по формату остальных файлов репозитория, `import-lookup-tables.js` проходит проверку синтаксиса. На живом Graylog 7.2.1 они ещё не запускались. Тип поля `tl_ioc_conf` и сработку правил проверьте по шагу 6.

## Как это устроено

```
TrafficLens (Podman, redos-server)
  │
  ├─ GELF UDP ──▶ вход GELF UDP :12205 ──▶ поток «TrafficLens» (tl_source = trafficlens)
  │                                           ├─ TRAFFICLENS - Компрометация по итогам анализа трафика
  │                                           ├─ TRAFFICLENS - Обращение к индикатору компрометации
  │                                           ├─ TRAFFICLENS - Ретропроверка: прошлый трафик совпал с новым IOC
  │                                           └─ TRAFFICLENS - Подозрительный трафик (без письма)
  │
  └─ HTTP /export/iocs.csv ◀── адаптер «DSV File from HTTP» (раз в час)
                                  └─ Lookup Table trafficlens-iocs
                                       └─ pipeline «trafficlens: ioc match»
                                            kn_ban_ip / src_ip / IpAddress → tl_ioc_hit, tl_ioc_info
                                            └─ TRAFFICLENS - Адрес из базы IOC в логах хостов
```

## Шаг 1. Вход GELF

Для TrafficLens заведён отдельный вход: в лаборатории порты 12201–12203 уже заняты другими входами (12203 — GraylogRuleTester, глава 16), поэтому выбран **12205**. Так по счётчику входа сразу видно, приходит ли что-то от TrafficLens.

System → Inputs → **GELF UDP** → Launch new input:

- Title: `TrafficLens`;
- Bind address: `0.0.0.0`;
- Port: `12205`.

Свободен ли порт, проверьте до создания: `ss -ulnp | grep 12205` ничего не должен вывести. Открывать порт в firewalld не нужно, если TrafficLens работает на том же хосте: из rootless-контейнера с сетью pasta пакеты на `host.containers.internal` приходят на хост как локальные. Если TrafficLens на другой машине, откройте порт: `firewall-cmd --permanent --add-port=12205/udp && firewall-cmd --reload`.

Можно отправлять и на уже существующий вход GELF UDP: сообщения TrafficLens отличаются полем `tl_source`, поток из шага 3 их отделит.

## Шаг 2. TrafficLens: отправка и выгрузка

В `~/.config/trafficlens.env` на хосте TrafficLens:

```bash
TL_GELF_HOST=host.containers.internal   # Graylog на том же хосте; иначе его адрес
TL_GELF_PORT=12205
TL_BASE_URL=https://trafficlens.example # ссылки на отчёт в сообщениях
TL_EXPORT_TOKEN=<токен>                 # python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

`host.containers.internal` — адрес хоста изнутри rootless-контейнера Podman. Адрес `127.0.0.1` из контейнера ведёт в сам контейнер, а не на хост.

```bash
systemctl --user restart trafficlens
curl -s "http://127.0.0.1:8095/export/iocs.csv?token=<токен>&types=ip&header=0" | head -3
```

В веб-интерфейсе TrafficLens: «Индикаторы и правила» → «Интеграция с Graylog» → «Отправить тестовое сообщение». В Graylog оно находится запросом `tl_event:test`.

Порог отправки задаётся в `trafficlens.yaml`: `gelf.min_level: suspicious` (по умолчанию) или `critical`. Подробно о полях сообщений — в [docs/graylog.md](https://github.com/ArsIS-02/TrafficLens/blob/main/docs/graylog.md) TrafficLens.

## Шаг 3. Поток «TrafficLens»

Streams → Create stream:

- Title: `TrafficLens`;
- Index set: Default (или свой, если вы держите отдельные индексы под источники);
- **Remove matches from 'Default Stream'**: включено.

Правило потока: поле `tl_source`, тип **match exactly**, значение `trafficlens`. Запустите поток и проверьте, что в нём есть тестовое сообщение.

## Шаг 4. Алерты

Определения лежат в [graylog/trafficlens-event-definitions.json](../graylog/trafficlens-event-definitions.json). Замените плейсхолдеры: `<TRAFFICLENS_STREAM_ID>` — ID потока из шага 3, `<NOTIFICATION_ID>` — ваше уведомление (например, копия «Mail.ru Alert Linux»). У последнего правила потоки `<SYSLOG_STREAM_ID>`, `<AUDITD_STREAM_ID>` и `<WINDOWS_STREAM_ID>`, как в остальных файлах.

| Определение | Запрос | Важность | Повтор |
|---|---|---|---|
| Компрометация по итогам анализа трафика | `tl_event:verdict AND tl_level:critical` | high | по задаче (`job`) |
| Обращение к индикатору компрометации | `tl_event:ioc_hit AND tl_ioc_conf:>=70` | high | по индикатору, не чаще раза в час |
| Ретропроверка: прошлый трафик совпал с новым IOC | `tl_event:retro_hit` | high | по индикатору |
| Подозрительный трафик | `tl_event:verdict AND tl_level:suspicious` | low | только событие, без письма |
| Адрес из базы IOC в логах хостов | `tl_ioc_hit:true` | high | по адресу, не чаще раза в час |

В событиях есть поля `host` (адреса), `host_name` (имена из TrafficLens), `tl_report` (ссылка на отчёт) и, для IOC, `ioc`, `ioc_type`, `ioc_source`, `ioc_info`. Их можно вывести в шаблон письма.

Повторной отправки нет: TrafficLens запоминает, что уже ушло по каждой задаче. После «Пересверить IOC» в Graylog приходят только новые совпадения, а итог отправляется повторно, только если он стал строже.

## Шаг 5. База IOC как Lookup Table

1. **System → Configurations → URL Whitelist → Add.** Тип Regex, значение
   `^http://127\.0\.0\.1:8095/export/iocs\.csv\?.*$`. Graylog 7 скачивает по HTTP только адреса из этого списка.
2. Таблица создаётся скриптом [`import-lookup-tables.js`](../graylog/pipelines/import-lookup-tables.js). Откройте Graylog, F12 → Console, вставьте файл целиком:
   ```js
   const URL = 'http://127.0.0.1:8095/export/iocs.csv?token=<токен>&types=ip,domain&header=0';
   await importLookupTables({only: ['trafficlens-iocs'], trafficlensUrl: URL, dryRun: true})
   await importLookupTables({only: ['trafficlens-iocs'], trafficlensUrl: URL})
   ```
   Скрипт создаёт кэш `trafficlens-iocs-cache`, адаптер `trafficlens-iocs-http` типа «DSV File from HTTP» и таблицу `trafficlens-iocs`. Адаптер берёт колонки по номерам: ключ `0` (адрес или домен), значение `3` (описание индикатора). Строку заголовка он не пропускает, поэтому в URL стоит `header=0`. Файл перечитывается раз в час.
3. Проверка: `/api/system/lookup/tables/trafficlens-iocs/query?key=<адрес из выгрузки>` возвращает описание.

Почему HTTP, а не файл на сервере, как у остальных таблиц: база IOC меняется каждый день, и копировать её руками в `/etc/graylog/server/lookups` бессмысленно. Graylog сам забирает свежую выгрузку.

## Шаг 6. Pipeline: сверка адресов из логов

Правила:

| Файл | Правило | Поле |
|---|---|---|
| [`trafficlens-ioc-keenetic-ban-ip.rule`](../graylog/pipelines/rules/trafficlens-ioc-keenetic-ban-ip.rule) | `trafficlens: ioc keenetic ban IP` | `kn_ban_ip` (глава 19) |
| [`trafficlens-ioc-linux-login-src-ip.rule`](../graylog/pipelines/rules/trafficlens-ioc-linux-login-src-ip.rule) | `trafficlens: ioc linux login src_ip` | `src_ip` (глава 4) |
| [`trafficlens-ioc-windows-src-ip.rule`](../graylog/pipelines/rules/trafficlens-ioc-windows-src-ip.rule) | `trafficlens: ioc windows src IP` | `winlogbeat_winlog_event_data_IpAddress` |

При совпадении каждое правило ставит `tl_ioc_hit=true`, `tl_ioc_ip` (адрес) и `tl_ioc_info` (описание из базы).

1. Загрузите правила: `python3 build_rules_json.py`, затем `import-rules.js` (см. [graylog/pipelines/README.md](../graylog/pipelines/README.md)).
2. Создайте **отдельный** pipeline `trafficlens: ioc match`. Запись pipeline через API заменяет его целиком, поэтому существующие не трогаем. Стадии:
   - одна стадия, режим `match either`, все три правила. Номер стадии должен быть больше, чем у правил, которые ставят `kn_ban_ip` и `src_ip` (`keenetic: lockout ban IP`, `homelab: linux login src_ip`): pipeline одного потока выполняются общими стадиями, и раньше времени правило увидит сообщение без поля (см. «Почему стадия 2» в README pipelines). Посмотрите стадии этих правил в своих pipeline и возьмите следующую.
3. Подключите pipeline к потокам `Syslog Logs`, `RedOS auditd Logs` и `WindowsLogs`.
4. Проверка:
   - в **System → Pipelines → trafficlens: ioc match** счётчик `not-matched` правил растёт: правило видит сообщения;
   - для проверки совпадения добавьте в TrafficLens свой IOC с адресом, который точно появится в логах (например, адрес ноутбука, с которого вы заходите по SSH), подождите обновления адаптера или нажмите в адаптере «Refresh»;
   - в поиске `tl_ioc_hit:true`; потом удалите тестовый IOC.
5. После первого сообщения с `tl_ioc_conf` в **System → Indices → Index set → Field types** убедитесь, что поле числовое (`long`). Если поле строковое, запрос `tl_ioc_conf:>=70` сравнивает строки; тогда задайте тип вручную (Change field type → Number) и ротируйте индекс.

## Ограничения

- Адаптер DSV сравнивает ключи точно, без CIDR. Подсети из базы (Spamhaus DROP и т. п.) в таблицу не выгружаются: их проверяет сам TrafficLens при анализе трафика.
- Домены в выгрузке есть, но правил для DNS-логов в этой главе нет: в лаборатории DNS-запросы в Graylog не собираются. Если собираете (FreeIPA bind, AdGuard, Pi-hole), добавьте такое же правило на поле с именем запроса.
- Токен выгрузки виден в настройках адаптера всем администраторам Graylog. Это токен только на чтение базы IOC, но не используйте его повторно для других целей.
- Отправка по UDP может терять сообщения при перегрузке входа. Для TrafficLens это десятки сообщений в день, но если важна гарантия доставки, создайте вход GELF TCP (например, тоже на `12205`: TCP и UDP на одном номере не конфликтуют) и задайте `gelf.protocol: tcp`.

## Что дальше

- Базовая линия «впервые увиденное»: новые внешние адреса и домены у хоста относительно его обычного поведения.
- Дашборд потока TrafficLens: итоги по дням, топ индикаторов, хосты с наибольшим риском.
- Правило для DNS-логов, когда они появятся в Graylog.

## Файлы

| Файл | Зачем |
|---|---|
| [`graylog/trafficlens-event-definitions.json`](../graylog/trafficlens-event-definitions.json) | пять определений событий с плейсхолдерами |
| [`graylog/pipelines/rules/trafficlens-ioc-*.rule`](../graylog/pipelines/rules/) | сверка адресов из логов с базой IOC |
| [`graylog/pipelines/rules.json`](../graylog/pipelines/rules.json) | все правила для `import-rules.js` (пересобран из `rules/`) |
| [`graylog/pipelines/import-lookup-tables.js`](../graylog/pipelines/import-lookup-tables.js) | таблица `trafficlens-iocs` с адаптером «DSV File from HTTP» |

Лицензия: GPL-3.0, как и весь репозиторий.
