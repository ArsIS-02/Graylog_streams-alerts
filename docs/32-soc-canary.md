# Глава 32. Сквозной canary Graylog → TicketBridge → IRIS

## Задача

Доступность API поодиночке не доказывает, что алерт действительно проходит всю цепочку. Для этого
на `redos-server` работает ежедневный контрольный прогон: безопасное GELF-сообщение с уникальным
ID должно стать событием Graylog, пройти через TicketBridge, создать алерт IRIS и инициировать
штатное уведомление `alert_created`.

Успешный тест автоматически закрывает **только собственный** алерт: `Closed` + `Legitimate`.
Это контрольная системная активность, а не реальная угроза и не False Positive.

## Изоляция от боевых правил

- Отдельное определение Graylog: `HEALTH - SOC canary: сквозная проверка`.
- Запрос: `soc_canary:true`; группировка по уникальному `soc_canary_id`.
- Приоритет Low: TicketBridge создаёт IRIS alert, но не создаёт заявку GLPI.
- Подключено только уведомление `GLPI Ticket (TicketBridge)`; мгновенного email Graylog нет.
- MITRE-полей нет, поэтому техника не удваивает скор. Одиночный Low не достигает порога
  автоэскалации в кейс.
- Существующий поток `Canary` относится к сетевым ловушкам (`homelab_app=canary`) и не меняется.

## Проверяемые стадии

1. Gzip GELF UDP отправляется на вход `Homelab tools` (`127.0.0.1:12206`). NUL-терминатор для UDP
   не используется.
2. Absolute search находит исходное сообщение по точному `soc_canary_id`.
3. `/api/events/search` находит событие только выделенного event definition.
4. IRIS alert ищется по уникальному ID в его собственных полях. Совпадения с чужим ID или просто
   последний алерт в списке не принимаются.
5. Алерт закрывается со статусами `alert_status_id=6`, `alert_resolution_status_id=6`, затем
   добавляется технический комментарий. Повторный GET подтверждает оба статуса.

Стандартные тайм-ауты: сообщение Graylog — 90 с, событие Graylog — 180 с, алерт IRIS — 180 с,
подтверждение закрытия — 60 с. Времена по стадиям и общая задержка записываются в JSON.

## Расписание и эксплуатация

Пользовательские systemd-юниты `soc-canary.service` и `soc-canary.timer`; ежедневно в **09:13**
локального времени сервера (Asia/Yekaterinburg), `Persistent=true`.

```bash
systemctl --user start soc-canary.service
systemctl --user status soc-canary.service --no-pager
systemctl --user list-timers soc-canary.timer
```

Повторный ручной запуск безопасен: предыдущий контрольный алерт уже закрыт, поэтому TicketBridge
создаёт новый алерт с новым ID, а не обогащает старый.

Файлы на сервере:

- `/home/redos/zabbix-suite/soc_canary.py`;
- `/home/redos/zabbix-suite/canary.env` — локальный URL Graylog, без токенов;
- `/home/redos/zabbix-suite/canary-state.json` — последний прогон;
- `/home/redos/zabbix-suite/canary-history/` — история, права файлов `0600`.

Секреты берутся из существующих `ticketbridge.env` и `watchdog.env`, в отчёты не выводятся.

## Независимый сигнал о сбое

На хосте `homeserver.monitoring.test` в Zabbix созданы trapper-метрики:

- `soc.canary.heartbeat` — время последнего завершённого прогона;
- `soc.canary.status` — `1` при успехе, `0` при сбое;
- `soc.canary.latency` — сквозная задержка в секундах.

Один триггер `SOC canary failed or heartbeat is stale` срабатывает при `status=0` или heartbeat
старше 26 часов. Это исключает пачку отдельных инцидентов по стадиям. Следующий успешный прогон
возвращает метрики и штатно закрывает проблему. Если Zabbix trapper недоступен, используется
существующий authenticated GELF fallback с одним постоянным event ID на сутки и последующим
`RESOLVED`.

## Границы проверки уведомлений

Создание неназначенного алерта запускает в IRIS обработчик `alert_created` с email-каналом. При
автозакрытии IRIS также запускает уведомление об изменении статуса, поэтому контрольный прогон может
создать два письма. Успешное выполнение email-задачи worker'ом подтверждает работу отправляющего
контура, но не доставку в почтовый ящик; последнюю нужно проверять отдельно по SMTP и ящику.

## Настройка и восстановление

Исходники находятся в репозитории TicketBridge: `tools/soc_canary.py`, `tools/soc-canary.service`,
`tools/soc-canary.timer`, `tools/canary.env.example`; тесты — `tests/test_soc_canary.py`.

`setup` по умолчанию выполняет только dry-run. `--apply` перед записью сохраняет определения и
уведомление в `/home/redos/ticketbridge/backups/soc-canary-<timestamp>/`, затем повторно читает и
проверяет созданное правило.

```bash
python3 tools/soc_canary.py setup
python3 tools/soc_canary.py setup --apply
python3 -m pytest -q tests/test_soc_canary.py
```

## Контрольный прогон 17.11.2026

Успешный прогон `soc-canary-9bac0d1f855048e0b7afe06cce07cade`:

- сообщение Graylog: `38976220-e28c-11f1-9fef-de2ac1f13cb9`;
- событие Graylog: `01M7MVQFEN2G10NW7TES2ZW7E1`;
- IRIS alert №1174, подтверждены `Closed` и `Legitimate`, технический комментарий №217;
- ожидание сообщения — 5,211 с, события — 25,232 с, алерта IRIS после события — 0,248 с;
- общая сквозная задержка — **31,096 с**;
- Zabbix items 50814–50816 получили heartbeat/status/latency, trigger 25726 находится в OK;
- IRIS worker успешно выполнил две email-задачи (создание и закрытие); доставка в ящик не проверялась.

Два предварительных прогона помогли исправить транспорт: UDP GELF должен быть gzip без
NUL-терминатора, а маркер `soc_canary` передаётся строкой `true`, поскольку boolean-поле в
принятом сообщении не сохранилось. Оба сбоя были зафиксированы canary и переданы в Zabbix.
