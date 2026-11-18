# Глава 34. Тюнинг контейнерных детекторов и maintenance-режим TicketBridge

> Ревизия детекторов «всплеск ошибок» показала: три четверти срабатываний — не ошибки
> приложений, а слово `error` внутри info-строк и warn-шум. Общий детектор починён (v2),
> caddy и blackbox вынесены в отдельные детекторы доступности. В TicketBridge добавлен
> режим обслуживания: на время плановых работ события не дублируются в IRIS и не плодят
> кейсы, оставаясь в Graylog с аудируемым маркером.

## Зачем

18.11 корреляция TicketBridge создала 8 кейсов IRIS — и все 8 оказались нашими же
плановыми работами (SSH-харденинг, миграция wyl, отладка WireGuard). Две причины:
детекторы считали «ошибки» по слову, а не по смыслу; эскалация не знала, что у актива
идёт кампания. Глава фиксирует лечение обеих.

## Ревизия «Контейнеры: всплеск ошибок» (6ad46833cc18050c4f225c18)

77 срабатываний за 3 суток: blockboard 15 (реальные, «database is locked»),
blackbox 10, caddy 9, grafana 8, остальное по мелочи.

### Три находки

1. **Поле GELF `level` — не severity.** У большинства контейнеров `level=3` означает
   «написано в stderr»: iris3test_app, homewiki, atrium пишут INFO-строки с level=3.
   Использовать `level:[0 TO 3]` для детектов нельзя — только текстовый `loglevel`
   (есть у loki-формата) и анализ message.
2. **`warn` в loglevel-части — чистый шум:** caddy «aborting with incomplete response»,
   grafana `middleware.gzip Failed to write gzipped response`.
3. **Голый токен `error` в message ловит вложенность:** nginx
   `[info] SSL_write() failed (SSL: error:80000020...)` (broken pipe от клиента),
   dozzle `{"level":"warn","error":"context deadline exceeded"}`, netalertx
   `⚠ ERROR - TIMEOUT - the plugin INTRNT forcefully terminated` (периодический таймаут
   плагина проверки интернета).

### Query v2 (18.11)

```
(loglevel:(error OR fatal) OR message:(error OR fatal OR panic OR exception OR traceback))
AND _exists_:container_name
AND NOT container_name:(cadvisor OR fluent-bit OR promtail OR blackbox OR caddy)
AND NOT message:"SSL_write() failed"
AND NOT (container_name:dozzle AND message:"context deadline exceeded")
AND NOT (container_name:netalertx AND message:"forcefully terminated")
```

Порог прежний: count() > 10 за 5 мин по container_name. Контроль на истории: 153 строки/24 ч
до правки → 45 после; остаток — реальные grafana «Request Completed» 5xx и единичный шум.

## Детекторы доступности

Доступность сервисов теперь меряется отдельно от «ошибок приложений» — двумя глазами:

| Детектор | ID | Query | Порог |
|---|---|---|---|
| Доступность: всплеск ошибок проб blackbox | 6afd980e61b983feab7f1438 | `container_name:blackbox AND message:"Probe failed"` | >5 за 5 мин, группировка по `bb_target` |
| Доступность: всплеск ошибок прокси caddy | 6afdbbe961b983feab7f3a17 | `container_name:caddy AND message:"http.log.error"` | >10 за 5 мин |

- `bb_target` (цель пробы) извлекается pipeline-правилом «containers: blackbox parse target»
  в пайплайне Container logs — в тексте события сразу видно, какой сервис лёг.
- caddy-детектор ловит недоступность upstream по реальным запросам (`dial tcp ...:
  connection refused`, `i/o timeout`). Blackbox смотрит снаружи по расписанию — пара
  покрывает обе перспективы; одновременные алерты по одной цели — один инцидент.
- Боевой тест 18.11 17:35–17:52 (остановка wyl): blackbox-детектор сработал дважды
  (count=19/20) с правильной целью, после подъёма wyl caddy-ошибки прекратились (0 за вечер).

## Maintenance-режим TicketBridge

`~/ticketbridge/app.py` (`_correlated_send`), бэкап `app.py.bak-maintenance-20261118`.

```bash
python3 ~/ticketbridge/tools/maintenance.py on 8 "*" "харденинг SSH"  # включить
python3 ~/ticketbridge/tools/maintenance.py status                    # состояние
python3 ~/ticketbridge/tools/maintenance.py off                       # выключить
```

- Файл `~/ticketbridge/maintenance.json`: `{"until": epoch, "assets": ["*"]|[имена],
  "comment": "..."}`; читается на каждое событие (кэш по mtime), рестарт не нужен,
  по `until` отключается сам.
- Пока активен: события **не дублируются в IRIS** (ни алерты, ни кейсы, скор не копится);
  в Graylog остаются + маркер `tb_event:maintenance_suppressed` с ключом корреляции —
  подавленное аудируемо.
- E2E-тест 18.11: maintenance on → триггер правила sudo → в Graylog маркер
  `maintenance — подавлено (6ad2f614f79a5f5fc59ed450|redos-server…)`, в IRIS пусто.

## Веса админских правил (TB_RULE_WEIGHTS)

Правилам, которые по природе ловят админскую работу, назначен вес 40
(×2 MITRE = 80 < 100): одиночное срабатывание создаёт **алерт, но не кейс**;
кейс — со второго за 24 ч.

| Правило | Вес |
|---|---|
| LNX - Добавление SSH-ключа в authorized_keys (…dafa) | 40 |
| LNX - Добавление/удаление пользователя (…d448) | 40 |
| LNX - Запуск из /tmp, /dev/shm, /var/tmp (…d7ee) | 40 |
| LNX - Отключение аудита или удаление правил auditd (…d7db7) | 40 |
| macOS - Bi.Zone: неизвестный SSH-ключ (…904c) | 40 |
| macOS - Keychain dump (…b115b), было 90 | 40 |
| DIFFWATCH - Изменение автозагрузки (…b275f) | 20 |

Бэкап env: `ticketbridge.env.bak-weights-20261118`. Полная матрица — статья
«IRIS - Полная матрица весов правил» в HomeWiki (регенерируется
`~/ticketbridge/update_weights_matrix.py`).

## Бэкапы и контроль

- Детекторы до/после: `~/ticketbridge/backups/container-spike-20261118/` на redos-server.
- Экспорт контейнерных детекторов в репо: `graylog/container-event-definitions.json` (20 шт.).
- Страницы HomeWiki: правила 6afd980e…, 6afdbbe9…, 6ad46833… + статья
  «TicketBridge - Режим обслуживания (maintenance)».
- Утренняя сверка 19.11 — первая проверка: ожидание «0 кейсов от фоновых событий».

## Грабли, чтобы не наступить снова

- Не добавлять `warn` в детекторы ошибок контейнеров — warn у инфраструктурных
  приложений (caddy, grafana) означает «клиент отвалился», а не «сервису плохо».
- Не использовать GELF `level` как severity — это stdout/stderr.
- Исключения писать точечно (контейнер + фраза), а не выключать контейнер целиком:
  iris3test_nginx исключён только по `SSL_write() failed`, прочие его ошибки видны.
- Maintenance — только с комментарием: по маркерам suppression через неделю
  не восстановить контекст без него.
