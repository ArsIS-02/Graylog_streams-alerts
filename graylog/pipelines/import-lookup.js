/*
 * Создаёт Lookup Table «доверенные хосты»: кэш, адаптер (CSV-файл на сервере Graylog) и таблицу.
 * Каждый объект ищется по названию: что есть, то остаётся без изменений.
 *
 * Сначала положи файл на сервер Graylog (пример: lookups/trusted-hosts.csv.example):
 *   sudo install -d -m 750 -o root -g graylog /etc/graylog/server/lookups
 *   sudo cp trusted-hosts.csv.example /etc/graylog/server/lookups/trusted-hosts.csv
 *   sudo chown root:graylog /etc/graylog/server/lookups/trusted-hosts.csv && sudo chmod 640 /etc/graylog/server/lookups/trusted-hosts.csv
 *
 * Запуск: открой Graylog в браузере (залогинься), F12 → Console, вставь файл целиком, затем:
 *   await importTrustedHostsLookup({dryRun: true})    // только показать, что будет создано
 *   await importTrustedHostsLookup()                  // создать
 * Если Graylog открыт не с корня: {base: '/graylog'}. Другой путь к файлу: {path: '/...'}.
 */
async function importTrustedHostsLookup(opts = {}) {
  const base = (opts.base || '').replace(/\/$/, '');
  const dry = !!opts.dryRun;
  const path = opts.path || '/etc/graylog/server/lookups/trusted-hosts.csv';
  const H = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Requested-By': 'XMLHttpRequest'};
  const api = async (method, url, body) => {
    const r = await fetch(base + url, {method, headers: H, credentials: 'same-origin',
      body: body ? JSON.stringify(body) : undefined});
    if (!r.ok) throw new Error(method + ' ' + url + ' → ' + r.status + ' ' + (await r.text()));
    return r.json();
  };
  const NAME = 'homelab-trusted-hosts';
  const report = [];
  const ensure = async (kind, listUrl, listKey, name, makeBody) => {
    const list = (await api('GET', listUrl + '?per_page=500'))[listKey] || [];
    const cur = list.find(x => x.name === name);
    if (cur) { report.push({объект: kind + ' ' + name, действие: 'уже есть'}); return cur; }
    report.push({объект: kind + ' ' + name, действие: dry ? 'создать (пробный запуск)' : 'создать'});
    return dry ? {id: '(новый)'} : api('POST', listUrl, makeBody());
  };

  const cache = await ensure('кэш', '/api/system/lookup/caches', 'caches', NAME + '-cache', () => ({
    name: NAME + '-cache', title: 'homelab: кэш доверенных хостов', description: 'Кэш таблицы ' + NAME,
    config: {type: 'guava_cache', max_size: 1000, expire_after_access: 60, expire_after_access_unit: 'SECONDS',
             expire_after_write: 0, expire_after_write_unit: null}}));
  const adapter = await ensure('адаптер', '/api/system/lookup/adapters', 'data_adapters', NAME + '-csv', () => ({
    name: NAME + '-csv', title: 'homelab: доверенные хосты (CSV)', description: 'Файл ' + path,
    config: {type: 'csvfile', path, separator: ',', quotechar: '"', key_column: 'key', value_column: 'value',
             check_interval: 60, case_insensitive_lookup: true, cidr_lookup: false, multi_value_lookup: false}}));
  await ensure('таблица', '/api/system/lookup/tables', 'lookup_tables', NAME, () => ({
    name: NAME, title: 'homelab: доверенные хосты', description: 'Хосты, для которых алерты можно подавлять',
    cache_id: cache.id, data_adapter_id: adapter.id,
    default_single_value: '', default_single_value_type: 'NULL', default_multi_value: '', default_multi_value_type: 'NULL'}));

  console.table(report);
  console.log(dry ? 'Пробный запуск: ничего не записано.' : 'Готово. Проверка: ' + base + '/api/system/lookup/tables/' + NAME + '/query?key=<имя хоста>');
  return report;
}
