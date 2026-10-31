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
