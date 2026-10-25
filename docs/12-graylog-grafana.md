# 12. Graylog + Grafana

Graylog — центр логов и алертов. Grafana в этой связке нужна для другого: собрать логи, метрики и состояние сервисов на одном экране. Готовые дашборды и подробности вынесены в отдельный репозиторий [grafana-homelab](https://github.com/ArsIS-02/grafana-homelab); здесь только то, что связывает его с Graylog.

## Что получаем

- **Логи Graylog** прямо в Grafana: объём сообщений, источники, facility, живой поиск.
- **Безопасность**: отказы SELinux, sudo, получение credentials, неудачные входы — из тех же потоков, что и алерты Graylog.
- **События Graylog как аннотации** на любом графике метрик: видно, какой алерт сработал в момент всплеска CPU.

## Как подключить

Grafana читает Graylog не через API Graylog, а напрямую из OpenSearch, где Graylog хранит сообщения. Нужны два источника данных типа Elasticsearch/OpenSearch:

| Источник | Индексы | Для чего |
|---|---|---|
| Graylog OpenSearch | `graylog_*` | панели с логами и безопасностью |
| Graylog Events | `gl-events_*` | аннотации с алертами |

Пароль OpenSearch в репозиторий не попадает: вводится в настройках источника.

## Аннотации

В дашборде добавьте аннотацию с источником «Graylog Events»: Query `alert:true`, Time field `timestamp`, Text field `message`, Tags field `source`. Подробности и подводные камни: [docs/03-annotations.md](https://github.com/ArsIS-02/grafana-homelab/blob/main/docs/03-annotations.md) в репозитории grafana-homelab.

## Грабли

- Удалили источник «для уборки» — все панели логов отвечают «Data source not found». Создайте его заново с тем же uid.
- Если Fluent Bit или MongoDB под SELinux шумят в журнале, это тоже видно на дашборде «Безопасность»; решения лежат в `scripts/` репозитория grafana-homelab.

Следующий шаг после этой главы — [troubleshooting](troubleshooting.md).
