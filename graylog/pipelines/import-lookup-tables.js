/*
 * Создаёт Lookup Tables лаборатории: для каждой кэш, адаптер (CSV-файл на сервере Graylog) и таблицу.
 * Каждый объект ищется по названию: что есть, то остаётся без изменений. Существующие данные
 * не затрагиваются, скрипт ничего не удаляет.
 *
 * 1) Положите CSV на сервер Graylog (файлы лежат в lookups/):
 *      sudo install -d -m 750 -o root -g graylog /etc/graylog/server/lookups
 *      sudo cp lookups/*.csv /etc/graylog/server/lookups/    # из каталога graylog/pipelines
 *      sudo chown root:graylog /etc/graylog/server/lookups/*.csv && sudo chmod 640 /etc/graylog/server/lookups/*.csv
 *
 * 2) Откройте Graylog в браузере (залогиньтесь), F12 → Console, вставьте файл целиком, затем:
 *      await importLookupTables({dryRun: true})    // только показать, что будет создано
 *      await importLookupTables()                  // создать
 *    Если Graylog открыт не с корня: {base: '/graylog'}. Каталог с файлами: {dir: '/...'}.
 *    Только часть таблиц: {only: ['homelab-windows-events']}.
 *
 * Таблицы подключаются к сообщениям правилами pipeline (rules/lookup-windows-*.rule), см. README.
 *
 * Таблица trafficlens-iocs берёт данные не из файла, а по HTTP из TrafficLens (глава 20). Она создаётся,
 * только если передан адрес выгрузки; сам адрес сначала добавьте в System → Configurations → URL Whitelist:
 *      await importLookupTables({only: ['trafficlens-iocs'],
 *        trafficlensUrl: 'http://127.0.0.1:8095/export/iocs.csv?token=<токен>&types=ip,domain&header=0'})
 */
const LOOKUP_TABLES = [
  {name: 'homelab-windows-events', file: 'windows-events.csv',
   title: 'homelab: коды событий Windows',
   description: 'EventID → название события (Security, Sysmon, PowerShell, службы)'},
  {name: 'homelab-windows-logon-types', file: 'windows-logon-types.csv',
   title: 'homelab: типы входа Windows',
   description: 'LogonType → смысл (2 Interactive, 3 Network, 10 RDP и т. д.)'},
  {name: 'homelab-windows-status', file: 'windows-status.csv',
   title: 'homelab: причины отказа входа Windows',
   description: 'Status / SubStatus из 4625 (0xc000006d …) → причина'},
  {name: 'homelab-host-roles', file: 'homelab-host-roles.csv',
   title: 'homelab: роли хостов', description: 'source (короткое и полное имя) → роль хоста'},
  {name: 'homelab-host-os', file: 'homelab-host-os.csv',
   title: 'homelab: ОС хостов', description: 'source (короткое и полное имя) → ОС'},
  {name: 'homelab-ip-names', file: 'homelab-ip-names.csv',
   title: 'homelab: IP → имя хоста', description: 'IP-адреса устройств лаборатории → имя'},
  {name: 'homelab-subnets', file: 'homelab-subnets.csv', cidr: true,
   title: 'homelab: подсети', description: 'IP → сеть (домашняя, loopback, частные), поиск по CIDR'},
  {name: 'homelab-syslog-severity', file: 'syslog-severity.csv',
   title: 'homelab: уровни syslog', description: 'level 0–7 → emergency … debug'},
  {name: 'homelab-auditd-types', file: 'auditd-types.csv',
   title: 'homelab: типы записей auditd', description: 'type → описание записи'},
  {name: 'homelab-keenetic-events', file: 'keenetic-events.csv',
   title: 'homelab: события Keenetic', description: 'kn_event_type → русское название'},
  {name: 'homelab-collector-agents', file: 'homelab-collector-agents.csv',
   title: 'homelab: агенты Collectors', description: 'agent_id → имя хоста'},
  {name: 'trafficlens-iocs', http: 'trafficlensUrl', key_column: 0, value_column: 3, refresh: 3600,
   title: 'TrafficLens: база IOC', description: 'Адрес или домен из базы IOC TrafficLens → описание индикатора (DSV по HTTP)'},
  {name: 'hostdeck-host-os', http: 'hostdeckUrl', query: 'key=name&header=0', key_column: 0, value_column: 2, refresh: 900,
   title: 'HostDeck: ОС хоста', description: 'Имя хоста (полное и короткое) → ОС из HostDeck (DSV по HTTP)'},
  {name: 'hostdeck-host-profile', http: 'hostdeckUrl', query: 'key=name&header=0', key_column: 0, value_column: 3, refresh: 900,
   title: 'HostDeck: профиль хоста', description: 'Имя хоста → профиль HostDeck: server, laptop, lab (DSV по HTTP)'},
  {name: 'hostdeck-ip-names', http: 'hostdeckUrl', query: 'key=ip&header=0', key_column: 0, value_column: 1, refresh: 900,
   title: 'HostDeck: адрес → имя', description: 'Адреса хостов из снимка сети и подписи с карты HostDeck → имя (DSV по HTTP)'},
  {name: 'homerepo-host-os', http: 'homerepoUrl', query: 'key=name&header=0', key_column: 0, value_column: 3, refresh: 900,
   title: 'HomeRepo: ОС устройства', description: 'Имя устройства (полное и короткое) → ОС из HomeRepo (DSV по HTTP)'},
  {name: 'homerepo-ip-names', http: 'homerepoUrl', query: 'key=ip&header=0', key_column: 0, value_column: 1, refresh: 900,
   title: 'HomeRepo: адрес → имя', description: 'Адреса устройств с агентом и найденных сканером → имя (DSV по HTTP)'},
];

async function importLookupTables(opts = {}) {
  const base = (opts.base || '').replace(/\/$/, '');
  const dry = !!opts.dryRun;
  const dir = (opts.dir || '/etc/graylog/server/lookups').replace(/\/$/, '');
  const only = opts.only || null;
  const H = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Requested-By': 'XMLHttpRequest'};
  const api = async (method, url, body) => {
    const r = await fetch(base + url, {method, headers: H, credentials: 'same-origin',
      body: body ? JSON.stringify(body) : undefined});
    if (!r.ok) throw new Error(method + ' ' + url + ' → ' + r.status + ' ' + (await r.text()));
    return r.json();
  };
  const report = [];
  const ensure = async (kind, listUrl, listKey, name, makeBody) => {
    const list = (await api('GET', listUrl + '?per_page=500'))[listKey] || [];
    const cur = list.find(x => x.name === name);
    if (cur) { report.push({объект: kind + ' ' + name, действие: 'уже есть'}); return cur; }
    report.push({объект: kind + ' ' + name, действие: dry ? 'создать (пробный запуск)' : 'создать'});
    return dry ? {id: '(новый)'} : api('POST', listUrl, makeBody());
  };

  for (const t of LOOKUP_TABLES) {
    if (only && !only.includes(t.name)) continue;
    if (t.http && !opts[t.http]) {
      report.push({объект: 'таблица ' + t.name, действие: 'пропущено: нет {' + t.http + ': ...}'});
      continue;
    }
    const cache = await ensure('кэш', '/api/system/lookup/caches', 'caches', t.name + '-cache', () => ({
      name: t.name + '-cache', title: t.title + ' (кэш)', description: 'Кэш таблицы ' + t.name,
      config: {type: 'guava_cache', max_size: 1000, expire_after_access: 60, expire_after_access_unit: 'SECONDS',
               expire_after_write: 0, expire_after_write_unit: null}}));
    const url = t.http ? opts[t.http] + (t.query ? (opts[t.http].includes('?') ? '&' : '?') + t.query : '') : '';
    const adapter = t.http
      ? await ensure('адаптер', '/api/system/lookup/adapters', 'data_adapters', t.name + '-http', () => ({
          name: t.name + '-http', title: t.title + ' (HTTP)', description: 'Выгрузка ' + url.replace(/token=[^&]*/, 'token=…'),
          config: {type: 'dsvhttp', url: url, refresh_interval: t.refresh, separator: ',',
                   line_separator: '\n', quotechar: '"', ignorechar: '#', key_column: t.key_column,
                   value_column: t.value_column, check_presence_only: false, case_insensitive_lookup: true}}))
      : await ensure('адаптер', '/api/system/lookup/adapters', 'data_adapters', t.name + '-csv', () => ({
          name: t.name + '-csv', title: t.title + ' (CSV)', description: 'Файл ' + dir + '/' + t.file,
          config: {type: 'csvfile', path: dir + '/' + t.file, separator: ',', quotechar: '"',
                   key_column: 'key', value_column: 'value', check_interval: 60,
                   case_insensitive_lookup: true, cidr_lookup: !!t.cidr, multi_value_lookup: false}}));
    await ensure('таблица', '/api/system/lookup/tables', 'lookup_tables', t.name, () => ({
      name: t.name, title: t.title, description: t.description,
      cache_id: cache.id, data_adapter_id: adapter.id,
      default_single_value: '', default_single_value_type: 'NULL',
      default_multi_value: '', default_multi_value_type: 'NULL'}));
  }

  console.table(report);
  console.log(dry ? 'Пробный запуск: ничего не записано.'
    : 'Готово. Проверка: ' + base + '/api/system/lookup/tables/homelab-windows-events/query?key=4625');
  return report;
}
