# 23. Кнопка «Разбор в HomeWiki» в письмах-алертах

Каталог детектов в [HomeWiki](https://github.com/ArsIS-02/homewiki) давно хранит страницу на каждое правило: описание, поисковый запрос, привязку к MITRE ATT&CK и примеры срабатываний из логов. Но чтобы попасть туда из письма о тревоге, нужно было вручную искать правило по названию. Теперь в каждом письме-алерте рядом с кнопкой «Открыть в Graylog» есть вторая — **«📖 Разбор в HomeWiki»**, которая ведёт прямо на страницу сработавшего правила.

> **Статус проверки.** На Graylog 7.2.1 (ноябрь 2026) обновлены все 9 уведомлений; живой GET каждого уведомления через API подтверждает наличие кнопки в HTML- и plain-шаблоне. Тестовое письмо (`POST /api/events/notifications/{id}/test`) проверено на десктопе и в мобильном почтовике: кнопки не накладываются, на узком экране переносятся друг под друга. Страницы новых правил (HOMEREPO, LOGATLAS, TRAFFICLENS и др.) открываются в HomeWiki по ссылке из письма.

## Схема URL — по ID определения

Шаблонный движок Graylog не умеет транслитерировать кириллические названия правил, зато в любом шаблоне доступен `${event_definition_id}` — стабильный идентификатор. В HomeWiki страницы правил изначально живут по адресу `/rules/<event_definition_id>` (так их садит `tools/collect.py`), поэтому ссылка строится безо всяких алиасов:

```
https://homewiki.apps.monitoring.test/rules/${event_definition_id}
```

Название правила можно менять — ссылка не сломается.

## Что изменилось в шаблонах

Во всех 9 уведомлениях (`Mail.ru Alert *`: Windows, Linux, MacOS, FreeIPA, Keenetic, Containers, IoC, Homelab tools, Daily Digest):

- в HTML-шаблон после кнопки «Открыть в Graylog» добавлена вторая кнопка (зелёная, `#a6e3a1` в той же Catppuccin-палитре письма):

  ```html
  <p style="margin-top:22px;line-height:2.8;">
  <span style="display:inline-block;margin:0 10px 10px 0;">
  <a href="https://redos-server.monitoring.test/graylog/alerts/${event.id}/replay-search"
     style="background:#89b4fa;color:#11111b;padding:9px 16px;border-radius:6px;
            text-decoration:none;font-weight:bold;font-size:14px;display:inline-block;">Открыть в Graylog</a></span>
  <span style="display:inline-block;margin:0 10px 10px 0;">
  <a href="https://homewiki.apps.monitoring.test/rules/${event_definition_id}"
     style="background:#a6e3a1;color:#11111b;padding:9px 16px;border-radius:6px;
            text-decoration:none;font-weight:bold;font-size:14px;display:inline-block;">📖 Разбор в HomeWiki</a></span>
  </p>
  ```

  Обёртки `inline-block` с внешним отступом и `line-height` у абзаца — это адаптация под мобильные почтовики: inline-ссылки с `&nbsp;` между ними при переносе на узком экране накладывались друг на друга (паддинги не влияют на высоту строки). Теперь на десктопе кнопки стоят в ряд, на телефоне переносятся друг под друга без наложений — даже там, где почтовик игнорирует `inline-block`, спасает высота строки.

- в plain-текст шаблон после строки «Открыть в Graylog: …» добавлена строка:

  ```
  📖 Разбор в HomeWiki: https://homewiki.apps.monitoring.test/rules/${event_definition_id}
  ```

Актуальные объекты уведомлений сохранены в [graylog/notifications.json](https://github.com/ArsIS-02/Graylog_streams-alerts/blob/main/graylog/notifications.json) — там же видно, как кнопка встроена в существующие конструкции `${if}/${foreach}`.

Обновление делалось через `PUT /api/events/notifications/{id}` сырым объектом с совпадающим `id` (заголовок `X-Requested-By` обязателен): все поля сохранены, менялись только `body_template` и `html_body_template`. Якорь для точечной замены — строка `Открыть в Graylog</a>` в HTML и `Открыть в Graylog: …replay-search` в plain-шаблоне.

## Синхронизация правил в HomeWiki

Чтобы ссылка из письма всегда куда-то вела, каталог должен покрывать **все** определения, а не только те, что были на момент первого запуска. Раньше `data.json` импортировался только в пустую базу; теперь при каждом старте HomeWiki:

- отсутствующие правила добавляются (`INSERT OR IGNORE`);
- правила без ручных правок (`edited=0`) обновляются: описание, запрос, стримы, MITRE, примеры;
- страницы, отредактированные в браузере, не трогаются.

Свежая выгрузка `tools/collect.py` подняла каталог с 219 до **240 правил** (добавились HOMEREPO, LOGATLAS, TRAFFICLENS и новые правила платформ). Деплой как обычно: пересборка образа `localhost/homewiki:latest` и перезапуск контейнера — база в `~/homewiki/data` на хосте, правки не теряются.

## Реакция на алерт с кнопкой

1. Письмо → «📖 Разбор в HomeWiki» → страница правила: что проверяет, запрос, техника MITRE со ссылкой на attack.mitre.org, примеры срабатываний за 30 дней.
2. Если контекста мало — кнопка «Открыть в Graylog» ведёт на повторный поиск события, а ссылка «Настройки алерта» — на определение.
3. Шаги реагирования дописываются прямо в HomeWiki (кнопка «Редактировать») — при следующих обновлениях каталога ручные правки сохранятся.
