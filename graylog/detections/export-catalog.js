/*
 * Выгрузка определений событий (алертов) Graylog в очищенный файл detections-source.json,
 * из которого build_catalog.py собирает каталог детектов (docs/14-detections.md).
 * Только чтение: ничего в Graylog не меняется.
 *
 * Запуск: откройте Graylog в браузере (залогиньтесь), F12 → Console, вставьте файл целиком, затем:
 *   await exportCatalog()                     // Graylog с корня сайта, скачает detections-source.json
 *   await exportCatalog({base: '/graylog'})   // Graylog под префиксом https://host/graylog/
 *   await exportCatalog({download: false})    // вернуть объект, ничего не скачивать
 *
 * Очистка: в названиях, запросах и описаниях IP-адреса заменяются на <IP>, MAC на <MAC>, отпечатки SHA256 на <отпечаток>,
 * внутренние домены и известные имена хостов — на <домен> и <хост>, а длинные списки исключений
 * (NOT поле:("…" OR "…")) с адресами или из шести и более значений — на <белый список>.
 * Всё равно просмотрите файл глазами перед публикацией: новые имена хостов скрипт не угадает.
 *
 * Дальше: положите файл в graylog/detections/ и запустите  python3 build_catalog.py
 */
function sanitizePrivate(t) {
  return t
    .replace(/\b[\w-]+(\.[\w-]+)*\.monitoring\.test\b/g, '<домен>')
    .replace(/\bmonitoring\\?\.test\b/g, '<домен>')
    .replace(/\b(redos-server|redosrp16|MacBook-Pro|MacMiniM2)\b/g, '<хост>');
}

function sanitizeQuery(q) {
  if (!q) return '';
  q = q.replace(/NOT ([\w.@]+):\(([^()]*)\)/g, (m, field, body) => {
    const n = (body.match(/"[^"]*"/g) || []).length;
    const sens = /\d+\.\d+\.\d+\.\d+|[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}|SHA256:/.test(body);
    return (sens || n >= 6) ? 'NOT ' + field + ':(<белый список>)' : m;
  });
  q = q
    .replace(/SHA256:[A-Za-z0-9+\/=]+/g, 'SHA256:<отпечаток>')
    .replace(/[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}/g, '<MAC>')
    .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, '<IP>');
  return sanitizePrivate(q);
}

function sanitizeText(t) {
  t = (t || '').split('\nMITRE ATT&CK')[0].trim()
    .replace(/[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}/g, '<MAC>')
    .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, '<IP>');
  return sanitizePrivate(t);
}

async function exportCatalog(opts = {}) {
  const base = (opts.base || '').replace(/\/$/, '');
  const H = {'Accept': 'application/json'};
  const api = async url => {
    const r = await fetch(base + url, {credentials: 'same-origin', headers: H});
    if (!r.ok) throw new Error(url + ' → ' + r.status);
    return r.json();
  };
  const defs = (await api('/api/events/definitions?per_page=1000')).event_definitions;
  const streams = Object.fromEntries((await api('/api/streams')).streams.map(s => [s.id, s.title]));
  const notifs = Object.fromEntries((await api('/api/events/notifications?per_page=500')).notifications.map(n => [n.id, n.title]));
  const tmpl = (fs, k) => (((fs || {})[k] || {}).providers || [{}])[0].template || null;

  const out = defs.filter(d => d.config && d.config.type === 'aggregation-v1').map(d => {
    const c = d.config;
    const ex = (c.conditions || {}).expression;
    const cond = ex && ex.right ? {op: ex.expr, value: ex.right.value} : null;
    return {
      title: sanitizeText(d.title),
      priority: d.priority,
      streams: (c.streams || []).map(id => streams[id] || id),
      notifications: (d.notifications || []).map(n => notifs[n.notification_id] || n.notification_id),
      state: d.state,
      description: sanitizeText(d.description),
      query: sanitizeQuery(c.query),
      group_by: c.group_by || [],
      condition: cond,
      aggregated: (c.series || []).length > 0,
      window_min: (c.search_within_ms || 0) / 60000,
      grace_min: ((d.notification_settings || {}).grace_period_ms || 0) / 60000,
      tactic: tmpl(d.field_spec, 'mitre_tactic'),
      technique: tmpl(d.field_spec, 'mitre_technique'),
      techniques: tmpl(d.field_spec, 'mitre_techniques'),
    };
  }).sort((a, b) => a.title.localeCompare(b.title));

  const doc = {generated: new Date().toISOString().slice(0, 10), source: 'Graylog', definitions: out};
  const leaks = JSON.stringify(doc).match(/\b\d{1,3}(\.\d{1,3}){3}\b|[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}/g);
  console.log('Определений: ' + out.length + (leaks ? '. ВНИМАНИЕ: в файле остались адреса: ' + leaks.slice(0, 5).join(', ') : '. Адресов и MAC в файле нет.'));
  if (opts.download === false) return doc;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(doc, null, 1)], {type: 'application/json'}));
  a.download = 'detections-source.json';
  a.click();
  return {определений: out.length};
}
