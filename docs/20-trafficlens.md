# 20. TrafficLens: анализ трафика и база IOC в Graylog

[TrafficLens](https://github.com/ArsIS-02/TrafficLens) разбирает записи сетевого трафика (Zeek, Suricata, свои и открытые базы IOC) и выносит итог: «Компрометация», «Подозрительно» или «Чисто». Эта глава связывает его с Graylog в обе стороны:

- **TrafficLens → Graylog.** Итоги анализа, совпадения с IOC и находки ретропроверки приходят по GELF в отдельный поток. По ним срабатывают алерты и уходят письма, как для остальных источников.
- **Graylog ← TrafficLens.** База IOC TrafficLens, которая каждый день пополняется из abuse.ch, C2IntelFeeds, Threatview, Spamhaus и других списков, подключается как Lookup Table. Pipeline сверяет с ней адреса из логов: баны Keenetic, входы в Linux и Windows. Так IOC работают не только для трафика, который прошёл через TrafficLens.

> **Статус проверки.** Собрано и запущено в лаборатории на Graylog 7.2.1 (ноябрь 2026). Проверено: тестовое сообщение TrafficLens доходит по UDP 12205 в поток «TrafficLens»; таблица `trafficlens-iocs` скачивает выгрузку и по адресу из базы возвращает описание индикатора; симулятор pipeline на бане Keenetic с адресом из базы ставит `tl_ioc_hit=true` и `tl_ioc_info`. Ещё не проверено: письмо на настоящую сработку (в трафике лаборатории пока не было совпадений с уверенностью от 70) и тип поля `tl_ioc_conf` в индексе (шаг 6, п. 5).

## Зачем связывать TrafficLens и Graylog

TrafficLens видит сеть, Graylog видит хосты. По отдельности каждый показывает половину картины.

1. **Находки трафика приходят туда же, куда всё остальное.** Без интеграции о совпадении с C2 узнаёшь, только если сам откроешь отчёт TrafficLens. С ней приходит письмо, как от детектов Windows или Keenetic, а событие лежит в общей ленте Alerts & Events. Особенно это важно для **ретропроверки**: «индикатор появился в базе сегодня, а хост ходил на него во вторник». Такое не заметишь, если специально не заглядывать.
2. **Сеть и хост в одном поиске.** TrafficLens скажет, что хост в 14:02 обращался к адресу Cobalt Strike, но не скажет, какой процесс это сделал. Это знает Graylog: auditd и Sysmon того же хоста за ту же минуту. Событие TrafficLens рядом с логами хоста превращает находку в расследование: сетевое обращение, запуск процесса и вход пользователя видны вместе.
3. **Одна база IOC работает и для логов.** TrafficLens каждый день собирает индикаторы примерно из двадцати источников. Через Lookup Table с этой базой сверяются адреса, которые банит Keenetic (видно, что это не случайный сканер, а адрес из списка C2 или известный атакующий), и адреса, с которых входят по SSH и в Windows. Для этого не нужны ни PCAP, ни захват: работает на тех логах, что уже есть. Список индикаторов ведётся в одном месте, а не в двух.

Чего пока нет: живой захват трафика в лаборатории не включён, TrafficLens разбирает только загруженные вручную записи. Событий из потока «TrafficLens» поэтому мало, в основном ретропроверка. Сверка банов и входов по базе IOC работает сразу.

## Как это устроено

```
TrafficLens (Podman, redos-server)
  │
  ├─ GELF UDP ──▶ вход «TrafficLens» GELF UDP :12205 ──▶ поток «TrafficLens» (tl_source = trafficlens)
  │                                           ├─ TRAFFICLENS - Компрометация по итогам анализа трафика   ─┐
  │                                           ├─ TRAFFICLENS - Обращение к индикатору компрометации      ─┤
  │                                           ├─ TRAFFICLENS - Ретропроверка: прошлый трафик совпал с IOC ─┤ письмо «Mail.ru Alert IoC» 🦠
  │                                           └─ TRAFFICLENS - Подозрительный трафик (без письма)         │
  │                                                                                                      │
  └─ HTTP /export/iocs.csv ◀── адаптер «DSV File from HTTP» (раз в час)                                  │
                                  └─ Lookup Table trafficlens-iocs                                       │
                                       └─ pipeline «trafficlens: ioc match», стадия 1                    │
                                            kn_ban_ip / src_ip / IpAddress → tl_ioc_hit, tl_ioc_info     │
                                            └─ TRAFFICLENS - Адрес из базы IOC в логах хостов ───────────┘
```

## Шаг 1. Вход GELF

Для TrafficLens заведён отдельный вход: в лаборатории порты 12201–12203 уже заняты другими входами (12203 — GraylogRuleTester, глава 16), поэтому выбран **12205**. Так по счётчику входа сразу видно, приходит ли что-то от TrafficLens.

System → Inputs → **GELF UDP** → Launch new input:

- Title: `TrafficLens`;
- Bind address: `0.0.0.0`;
- Port: `12205`;
- Global: включено (узел один); Override source оставить пустым, TrafficLens сам пишет `source: trafficlens`.

Перед созданием проверьте, что порт свободен: `ss -ulnp | grep 12205` ничего не выводит.

**firewalld.** Если TrafficLens работает на том же хосте, порт можно не открывать: из rootless-контейнера с сетью pasta пакеты на `host.containers.internal` приходят на хост как локальные. В лаборатории порт открыт так же, как соседний 12201, чтобы в этот вход могли слать и другие машины:

```bash
sudo firewall-cmd --permanent --zone=public --add-port=12205/udp
sudo firewall-cmd --reload
```

**SELinux.** Метка порта не нужна, если Graylog работает как `unconfined_service_t`. Проверка: `ps -eZ | grep [g]raylog` и `semanage port -l | grep 1220` (в лаборатории у 12201–12203 меток нет, все входы работают). Если Graylog у вас в ограниченном домене и вход не стартует с `denied { name_bind }` в `ausearch -m avc`, добавьте порту тот же тип, что у уже работающего входа: `semanage port -a -t <тип> -p udp 12205`.

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
podman exec trafficlens env | grep -E 'TL_GELF|TL_BASE|TL_EXPORT'      # переменные дошли до контейнера
curl -s "http://127.0.0.1:8095/export/iocs.csv?token=<токен>&types=ip&header=0" | head -3
```

`curl` должен вывести строки вида `адрес,ip,источник,описание,уверенность`. Ответ 404 означает, что токен в контейнер не попал.

В веб-интерфейсе TrafficLens: «Индикаторы и правила» → «Интеграция с Graylog» → «Отправить тестовое сообщение». В Graylog оно находится запросом `tl_event:test`. Если не пришло, на хосте `sudo tcpdump -ni any udp port 12205` во время нажатия кнопки покажет, доходят ли пакеты до входа.

Порог отправки задаётся в `trafficlens.yaml`: `gelf.min_level: suspicious` (по умолчанию) или `critical`. Подробно о полях сообщений — в [docs/graylog.md](https://github.com/ArsIS-02/TrafficLens/blob/main/docs/graylog.md) TrafficLens.

## Шаг 3. Поток «TrafficLens»

Streams → Create stream:

- Title: `TrafficLens`;
- Index set: Default (или свой, если вы держите отдельные индексы под источники);
- **Remove matches from 'Default Stream'**: включено.

Правило потока: поле `tl_source`, тип **match exactly**, значение `trafficlens`. Запустите поток и проверьте, что в нём есть тестовое сообщение.

## Шаг 4. Уведомление и алерты

### Уведомление «Mail.ru Alert IoC»

Все письма TrafficLens про индикаторы компрометации, поэтому для них отдельное уведомление, а не одно из уведомлений платформ. Файл: [graylog/trafficlens-notification-ioc.json](../graylog/trafficlens-notification-ioc.json). Это копия шаблона Keenetic (глава 2) с эмодзи 🦠:

- тема: `🦠 [HIGH] IoC: <название алерта> — <индикатор или хост>`;
- в письме: индикатор и его тип, описание и источник IOC, хосты (имена из TrafficLens и адреса), запись трафика, когда это было в трафике (для ретропроверки), причины итога;
- кнопки «Отчёт TrafficLens» (ссылка из `tl_report`) и «Открыть в Graylog»;
- в исходных сообщениях: `tl_event`, индикатор или адрес из логов, источник, хосты.

Создание: Alerts → Notifications → Create, тип Email, поля из файла. Замените `<your>@mail.ru` на свой адрес и `<Graylog server>` в ссылках на адрес своего Graylog.

### Алерты

Определения лежат в [graylog/trafficlens-event-definitions.json](../graylog/trafficlens-event-definitions.json). Замените плейсхолдеры: `<TRAFFICLENS_STREAM_ID>` — ID потока из шага 3, `<NOTIFICATION_ID>` — ID уведомления «Mail.ru Alert IoC». У последнего правила потоки `<SYSLOG_STREAM_ID>`, `<AUDITD_STREAM_ID>` и `<WINDOWS_STREAM_ID>`, как в остальных файлах.

| Определение | Запрос | Важность | Письмо | Повтор |
|---|---|---|---|---|
| Компрометация по итогам анализа трафика | `tl_event:verdict AND tl_level:critical` | high | да | по задаче (`job`) |
| Обращение к индикатору компрометации | `tl_event:ioc_hit AND tl_ioc_conf:>=70` | high | да | по индикатору, не чаще раза в час |
| Ретропроверка: прошлый трафик совпал с новым IOC | `tl_event:retro_hit` | high | да | по индикатору |
| Подозрительный трафик | `tl_event:verdict AND tl_level:suspicious` | low | нет | только событие для разбора, чтобы эвристики не засыпали почту |
| Адрес из базы IOC в логах хостов | `tl_ioc_hit:true` | high | да | по адресу, не чаще раза в час |

В событиях есть поля `host` (адреса), `host_name` (имена из TrafficLens), `tl_report` (ссылка на отчёт), `tl_file` и, для IOC, `ioc`, `ioc_type`, `ioc_source`, `ioc_info`. Их использует шаблон письма.

Повторной отправки нет: TrafficLens запоминает, что уже ушло по каждой задаче. После «Пересверить IOC» в Graylog приходят только новые совпадения, а итог отправляется повторно, только если он стал строже.

## Шаг 5. База IOC как Lookup Table

1. **System → Configurations → URL Allowlist → Add** (в старых версиях раздел назывался URL Whitelist). Тип Regex, значение
   `^http://127\.0\.0\.1:8095/export/iocs\.csv\?.*$`. Graylog скачивает по HTTP только адреса из этого списка.
2. Таблица создаётся скриптом [`import-lookup-tables.js`](../graylog/pipelines/import-lookup-tables.js). Откройте Graylog, F12 → Console, вставьте файл целиком:
   ```js
   const URL = 'http://127.0.0.1:8095/export/iocs.csv?token=<токен>&types=ip,domain&header=0';
   await importLookupTables({only: ['trafficlens-iocs'], trafficlensUrl: URL, dryRun: true})
   await importLookupTables({only: ['trafficlens-iocs'], trafficlensUrl: URL})
   ```
   Скрипт создаёт кэш `trafficlens-iocs-cache`, адаптер `trafficlens-iocs-http` типа «DSV File from HTTP» и таблицу `trafficlens-iocs`. Адаптер берёт колонки по номерам: ключ `0` (адрес или домен), значение `3` (описание индикатора). Строку заголовка он не пропускает, поэтому в URL стоит `header=0`. Файл перечитывается раз в час.
3. Проверка: `/api/system/lookup/tables/trafficlens-iocs/query?key=<адрес из выгрузки>` возвращает описание. В лаборатории для адреса из C2IntelFeeds ответ был `C2IntelFeeds — C2 IP (30 дней): Possible Cobaltstrike C2 IP`.

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
2. Создайте **отдельный** pipeline `trafficlens: ioc match`. Запись pipeline через API заменяет его целиком, поэтому существующие не трогаем. Одна стадия, режим `match either`, все три правила:
   ```
   pipeline "trafficlens: ioc match"
   stage 1 match either
   rule "trafficlens: ioc keenetic ban IP"
   rule "trafficlens: ioc linux login src_ip"
   rule "trafficlens: ioc windows src IP"
   end
   ```
   Номер стадии должен быть больше, чем у правил, которые ставят `kn_ban_ip` и `src_ip`: pipeline одного потока выполняются общими стадиями, и раньше времени правило увидит сообщение без поля (см. «Почему стадия 2» в README pipelines). В лаборатории `keenetic: lockout ban IP` (pipeline `Keenetic Processing`) и `homelab: linux login src_ip` (`homelab: linux enrichment`) стоят в стадии 0, а `IpAddress` Windows приходит в сообщении сразу, поэтому взята **стадия 1**.
3. Подключите pipeline к потокам `Syslog Logs`, `RedOS auditd Logs` и `WindowsLogs` (Manage connections). Прежние pipeline этих потоков остаются на месте, новый добавляется к ним.
4. Проверка без настоящих событий — **System → Pipelines → Simulate**: поток `Syslog Logs`, сообщение
   ```
   Keenetic-7625 ndm: Netfilter::Lockout::Manager: "Http": ban remote host <адрес из выгрузки> for 15 minutes.
   ```
   с `source` = имя роутера. В результате должны появиться `kn_ban_ip` (стадия 0), затем `tl_ioc_hit: true`, `tl_ioc_ip` и `tl_ioc_info` (стадия 1). В лаборатории так и вышло; в трассировке видно, что `keenetic: lockout ban IP` выполнилось раньше `trafficlens: ioc keenetic ban IP`. Для адреса не из базы `tl_ioc_hit` не появляется.
5. После первого сообщения с `tl_ioc_conf` в **System → Indices → Index set → Field types** убедитесь, что поле числовое (`long`). Если поле строковое, запрос `tl_ioc_conf:>=70` сравнивает строки; тогда задайте тип вручную (Change field type → Number) и ротируйте индекс.

## Грабли

- **REST Graylog 7: создание потока.** `POST /api/streams` с телом потока отвечает `400 entity cannot be null`. Тело нужно обернуть: `{"entity": {...поток...}, "share_request": {"selected_grantee_capabilities": {}}}`. Правила pipeline, сам pipeline и Lookup Tables создаются без обёртки. Для уведомлений и определений событий скрипт в лаборатории сначала пробовал запрос без обёртки и при такой же ошибке повторял его с обёрткой.
- **Консоль браузера не ходит на GitHub.** Политика безопасности страниц Graylog (CSP) запрещает `fetch` на внешние адреса, поэтому скачать `rules.json` или определения прямо из консоли не выйдет: содержимое файла нужно вставлять в консоль самому.
- **Симулятор через API требует `_id`.** Без поля `_id` в сообщении `POST /api/system/pipelines/simulate` падает с `500 message id cannot be null`. В веб-интерфейсе Simulate идентификатор подставляется сам.
- **Колонки DSV по номерам.** У адаптера «DSV File from HTTP», в отличие от CSV-адаптера, нет имён колонок и пропуска заголовка: ключ и значение задаются номерами с нуля, заголовок выключается в выгрузке (`header=0`).

## Ограничения

- Адаптер DSV сравнивает ключи точно, без CIDR. Подсети из базы (Spamhaus DROP и т. п.) в таблицу не выгружаются: их проверяет сам TrafficLens при анализе трафика.
- Домены в выгрузке есть, но правил для DNS-логов в этой главе нет: в лаборатории DNS-запросы в Graylog не собираются. Если собираете (FreeIPA bind, AdGuard, Pi-hole), добавьте такое же правило на поле с именем запроса.
- Токен выгрузки виден в настройках адаптера всем администраторам Graylog. Это токен только на чтение базы IOC, но не используйте его повторно для других целей.
- Отправка по UDP может терять сообщения при перегрузке входа. Для TrafficLens это десятки сообщений в день, но если важна гарантия доставки, создайте вход GELF TCP (например, тоже на `12205`: TCP и UDP на одном номере не конфликтуют) и задайте `gelf.protocol: tcp`.

## Что дальше

- Живой захват трафика на сервере, чтобы поток «TrafficLens» получал события не только от загруженных записей.
- Базовая линия «впервые увиденное»: новые внешние адреса и домены у хоста относительно его обычного поведения.
- Дашборд потока TrafficLens: итоги по дням, топ индикаторов, хосты с наибольшим риском.
- Правило для DNS-логов, когда они появятся в Graylog.

## Файлы

| Файл | Зачем |
|---|---|
| [`graylog/trafficlens-event-definitions.json`](../graylog/trafficlens-event-definitions.json) | пять определений событий с плейсхолдерами |
| [`graylog/trafficlens-notification-ioc.json`](../graylog/trafficlens-notification-ioc.json) | уведомление «Mail.ru Alert IoC»: тема, текст и HTML письма |
| [`graylog/pipelines/rules/trafficlens-ioc-*.rule`](../graylog/pipelines/rules/) | сверка адресов из логов с базой IOC |
| [`graylog/pipelines/rules.json`](../graylog/pipelines/rules.json) | все правила для `import-rules.js` (пересобран из `rules/`) |
| [`graylog/pipelines/import-lookup-tables.js`](../graylog/pipelines/import-lookup-tables.js) | таблица `trafficlens-iocs` с адаптером «DSV File from HTTP» |

Лицензия: GPL-3.0, как и весь репозиторий.
