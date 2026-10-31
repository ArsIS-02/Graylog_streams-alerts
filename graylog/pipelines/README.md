# Правила pipeline

Правила, которые в лаборатории работают на сервере Graylog 7.2.1. Здесь они лежат файлами,
чтобы их можно было восстановить на новом сервере и не вспоминать, что где менялось.

Текст каждого правила в этом каталоге совпадает с боевым. Сверено с работающим Graylog.

## Что внутри

| Файл | Правило | Зачем | Pipeline, стадия |
|---|---|---|---|
| `collectors-drop-kaspersky-flow-noise.rule` | `collectors: drop kaspersky flow noise` | Отбрасывает шум сетевого расширения Касперского на Маках (глава 11) | `Collector logs`, стадия 0 |
| `collectors-hostname-as-source.rule` | `collectors: hostname as source` | Короткое имя хоста вместо IP в `source` (глава 11) | `Collector logs`, стадия 1 |
| `containers-normalize-fields.rule` | `containers: normalize fields` | `CONTAINER_NAME` → `container_name`, `container_id`, `image_name` (глава 8) | `Container logs`, стадия 0 |
| `containers-log-new-expiration-text.rule` | `containers: log_new_expiration в строку` | Caddy шлёт дату строкой, а в индексе поле `long`: документ отбрасывается ([troubleshooting, п. 12](../../docs/troubleshooting.md)) | `Container logs`, стадия 1 |
| `lookup-trusted-hosts-flag.rule` | `homelab: пометить доверенные хосты` | Ставит `trusted_host=true`, если хост есть в Lookup Table (см. ниже) | отдельный pipeline `homelab: trusted hosts`, стадия 2, поток Collectors |
| `macos-truncate-cmdline.rule` | `macos: обрезать слишком длинный cmdline` | Командная строка osquery длиннее 32766 байт отбрасывается индексом ([п. 20](../../docs/troubleshooting.md)) | `macOS Log Processing`, стадия 0 |
| `macos-truncate-eventmessage.rule` | `macos: обрезать слишком длинный eventMessage` | То же для `eventMessage` ([п. 20](../../docs/troubleshooting.md)) | `macOS Log Processing`, стадия 2, в конце |

Правила самих Маков (`macOS 00` … `macOS 08`), Windows, Keenetic и FreeIPA сюда не входят: они
описаны в главах 3, 5 и 6, а правила `collectors: source <имя Мака>` привязаны к идентификатору
агента и у каждого свои.

## Как восстановить

1. Если нужно, пересобрать `rules.json` из файлов (первая строка `// description: ...`
   становится описанием правила, в источник она не попадает):

   ```bash
   python3 build_rules_json.py
   ```

2. Открыть Graylog в браузере (залогиниться), F12 → Console. Вставить `import-rules.js` целиком,
   затем `const SPEC = [...];` с содержимым `rules.json`.

3. Сначала пробный запуск, он ничего не записывает и показывает, что будет создано,
   обновлено или останется как есть:

   ```js
   await importRules(SPEC, {dryRun: true})
   ```

   Если Graylog открыт не с корня (`https://host/graylog/`), добавить `{base: '/graylog'}`.

4. Запись:

   ```js
   await importRules(SPEC)
   ```

   Правила находятся по названию. Если правило с таким названием есть, оно обновляется, если
   текст совпадает, остаётся без изменений.

5. Подключить правила к стадиям pipeline вручную: **System → Pipelines → нужный pipeline →
   Edit → Add new stage / rule**. Стадии из таблицы выше.

Скрипт нарочно не трогает сами pipeline. Запись pipeline через API заменяет его целиком и
стирает стадии, которых нет в теле запроса (см. главу 11, «Грабли», п. 4).

## Порядок внутри стадии

- Правила, меняющие поле (`abbreviate`, `set_field`), ставят **после** тех, что это поле
  создают. Обрезку `eventMessage` поэтому поставили в последнюю стадию macOS-pipeline.
- Режим стадии (`match all`, `match either`, `match pass`) определяет только то, перейдёт ли
  обработка к следующей стадии. Правила, у которых условие сработало, выполняются в любом
  режиме. В лаборатории `Container logs` и `macOS Log Processing` работают в режиме `either`,
  `Collector logs` в режиме `pass`.

## Списки исключений: Lookup Tables

Проверено на Graylog 7.2.1. Идея: не перечислять хосты `OR`-цепочкой в запросе каждого алерта, а
держать список в одном файле. Правило pipeline помечает сообщения от хостов из списка, а запрос
алерта исключает помеченные: `... AND NOT trusted_host:true`.

**Что умеет и чего не умеет.** Таблица ищет по **точному совпадению ключа** (регистр не важен, если
включён `case_insensitive_lookup`). Это подходит для имён хостов, IP и пользователей. Подстроки
в тексте сообщения она не заменяет: список вида `message:("hostdeck.apps.monitoring.test" OR ...)`
в запросе так и остаётся запросом.

**Как собрано в лаборатории:**

1. Файл списка на сервере Graylog ([`lookups/trusted-hosts.csv.example`](lookups/trusted-hosts.csv.example)),
   команды создания в начале `import-lookup.js`. Ключи: короткие имена, какими их видит `source`
   у сообщений Collectors. Правка `server.conf` (`allowed_auxiliary_paths`) в нашей установке не
   понадобилась.
2. Кэш, адаптер и таблица `homelab-trusted-hosts`: `import-lookup.js` (так же, как `import-rules.js`:
   сначала `{dryRun: true}`).
3. Правило `homelab: пометить доверенные хосты` ([`rules/lookup-trusted-hosts-flag.rule`](rules/lookup-trusted-hosts-flag.rule))
   в **отдельном** pipeline `homelab: trusted hosts`, стадия 2, подключённом к потоку Collectors
   (рядом с `Collector logs`, а не вместо него).
4. Проверка: запрос к таблице
   `/api/system/lookup/tables/homelab-trusted-hosts/query?key=server` возвращает `trusted`, для
   неизвестного хоста значение пустое; в поиске `trusted_host:true`.

**Почему стадия 2.** Pipeline, подключённые к одному потоку, выполняются общими стадиями:
сначала стадия 0 всех pipeline, потом стадия 1 и так далее. Имя хоста в `source` подставляет
`collectors: hostname as source` в стадии 1 pipeline `Collector logs`. В стадии 0 правило видело ещё
IP и не срабатывало ни разу: метрики показали `matched = 0` при растущем `not-matched` (за несколько
минут 2568). После переноса в стадию 2 все новые сообщения двух хостов получили метку, а другие
хосты нет. Метрики правила см. в главе 11, раздел «Проверка и диагностика».

**Что не сделано.**

- Ни одно определение события пока не использует `trusted_host`: в запросы алертов
  `AND NOT trusted_host:true` не добавлялось.
- Контейнерные логи из Fluent Bit (поток Containers) не помечаются. Для них в `source`
  полное имя (`host.monitoring.test`), поэтому в списке нужны ключи с полными именами, а pipeline нужно
  подключить и к этому потоку. Не проверялось.
- Правка файла списка после создания адаптера не проверялась: адаптер перечитывает файл раз в
  `check_interval` (в нашей настройке 60 секунд).

## Один хост, два имени источника

Поле `source` у одного и того же хоста может отличаться в зависимости от канала:

| Канал | Что в `source` | Пример |
|---|---|---|
| Collectors | короткое имя (правило `collectors: hostname as source`) | `wazuh-homelab` |
| Fluent Bit → GELF | полное имя из `HOSTNAME` | `wazuh-homelab.monitoring.test` |

Из-за этого запрос `source:wazuh-homelab` не находит контейнерные логи, а запрос по полному
имени не находит логи агента. Если нужно одно имя, добавьте такое же правило в pipeline
`Container logs`. В лаборатории это не включено: на полное имя завязаны существующие запросы,
дашборды и группировки алертов по `source`, и менять их все разом без проверки не стали.
