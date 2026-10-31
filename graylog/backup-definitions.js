/*
 * Резервная копия определений событий (алертов) Graylog 7.x в один JSON-файл.
 * Только чтение: ничего в Graylog не меняется.
 *
 * Запуск: откройте Graylog в браузере (залогиньтесь), F12 → Console, вставьте файл целиком, затем:
 *   await backupDefinitions()                       // Graylog с корня сайта
 *   await backupDefinitions({base: '/graylog'})     // Graylog под префиксом https://host/graylog/
 * Браузер скачает файл graylog-event-definitions-<дата>.json.
 *
 * Восстановление определения: PUT /api/events/definitions/{id}?schedule=true с телом из файла.
 */
async function backupDefinitions(opts = {}) {
  const base = (opts.base || '').replace(/\/$/, '');
  const H = {'Accept': 'application/json', 'X-Requested-By': 'XMLHttpRequest'};
  const get = async path => {
    const r = await fetch(base + path, {headers: H, credentials: 'same-origin'});
    if (!r.ok) throw new Error('GET ' + path + ' → ' + r.status + ' ' + (await r.text()));
    return r.json();
  };
  const list = await get('/api/events/definitions?per_page=1000');
  const defs = list.event_definitions || [];
  const full = [];
  for (const d of defs) full.push(await get('/api/events/definitions/' + d.id));
  const out = {
    exported_at: new Date().toISOString(),
    graylog_version: (await get('/api/system')).version,
    count: full.length,
    event_definitions: full,
  };
  const blob = new Blob([JSON.stringify(out, null, 2)], {type: 'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'graylog-event-definitions-' + new Date().toISOString().slice(0, 10) + '.json';
  document.body.appendChild(a); a.click(); a.remove();
  console.log('Сохранено определений: ' + full.length);
  return full.length;
}
