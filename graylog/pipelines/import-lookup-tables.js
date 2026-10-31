/*
 * Создаёт Lookup Tables лаборатории: для каждой кэш, адаптер (CSV-файл на сервере Graylog) и таблицу.
 * Каждый объект ищется по названию: что есть, то остаётся без изменений. Существующие данные
 * не затрагиваются, скрипт ничего не удаляет.
 *
 * 1) Положите CSV на сервер Graylog (файлы лежат в lookups/):
 *      sudo install -d -m 750 -o root -g graylog /etc/graylog/server/lookups
 *      sudo cp windows-events.csv windows-logon-types.csv /etc/graylog/server/lookups/
 *      sudo chown root:graylog /etc/graylog/server/lookups/*.csv && sudo chmod 640 /etc/graylog/server/lookups/*.csv
 *
 * 2) Откройте Graylog в браузере (залогиньтесь), F12 → Console, вставьте файл целиком, затем:
 *      await importLookupTables({dryRun: true})    // только показать, что будет создано
 *      await importLookupTables()                  // создать
 *    Если Graylog открыт не с корня: {base: '/graylog'}. Каталог с файлами: {dir: '/...'}.
 *    Только часть таблиц: {only: ['homelab-windows-events']}.
 *
 * Таблицы подключаются к сообщениям правилами pipeline (rules/lookup-windows-*.rule), см. README.
 */
const LOOKUP_TABLES = [
  {name: 'homelab-windows-events', file: 'windows-events.csv',
   title: 'homelab: коды событий Windows',
   description: 'EventID → название события (Security, Sysmon, PowerShell, службы)'},
  {name: 'homelab-windows-logon-types', file: 'windows-logon-types.csv',
   title: 'homelab: типы входа Windows',
   description: 'LogonType → смысл (2 Interactive, 3 Network, 10 RDP и т. д.)'},
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
    const cache = await ensure('кэш', '/api/system/lookup/caches', 'caches', t.name + '-cache', () => ({
      name: t.name + '-cache', title: t.title + ' (кэш)', description: 'Кэш таблицы ' + t.name,
      config: {type: 'guava_cache', max_size: 1000, expire_after_access: 60, expire_after_access_unit: 'SECONDS',
               expire_after_write: 0, expire_after_write_unit: null}}));
    const adapter = await ensure('адаптер', '/api/system/lookup/adapters', 'data_adapters', t.name + '-csv', () => ({
      name: t.name + '-csv', title: t.title + ' (CSV)', description: 'Файл ' + dir + '/' + t.file,
      config: {type: 'csvfile', path: dir + '/' + t.file, separator: ',', quotechar: '"',
               key_column: 'key', value_column: 'value', check_interval: 60,
               case_insensitive_lookup: true, cidr_lookup: false, multi_value_lookup: false}}));
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
