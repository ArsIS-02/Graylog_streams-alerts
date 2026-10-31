/*
 * Записывает в определения событий Graylog 7.x поля mitre_tactic, mitre_technique, mitre_techniques
 * (шаблоны template-v1 со статическим текстом). Определения находятся по названию.
 * Запуск: открой Graylog в браузере (залогинься), F12 → Console, вставь файл целиком, затем:
 *   const SPEC = {...};                                  // содержимое mitre-fields.json
 *   await importMitre(SPEC, {dryRun: true})              // только показать, что изменится
 *   await importMitre(SPEC)                              // записать
 * Если Graylog открыт не с корня (https://host/graylog/): {base: '/graylog'}.
 *
 * Перед записью скрипт сохраняет полные копии определений в localStorage (ключ defs_backup_<дата>).
 * Остальные поля определения (запрос, уведомления, field_spec) не меняются, добавляются только mitre_*.
 * В событиях поля лежат во вложенном объекте: в поиске и на дашбордах это fields.mitre_technique.
 */
async function importMitre(SPEC, opts = {}) {
  const base = (opts.base || '').replace(/\/$/, '');
  const dry = !!opts.dryRun;
  const H = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Requested-By': 'XMLHttpRequest'};
  const api = async (method, path, body) => {
    const r = await fetch(base + path, {method, headers: H, credentials: 'same-origin',
      body: body ? JSON.stringify(body) : undefined});
    if (!r.ok) throw new Error(method + ' ' + path + ' → ' + r.status + ' ' + (await r.text()));
    return r.json();
  };
  const mk = v => ({data_type: 'string', providers: [{type: 'template-v1', template: v,
    require_values: false, exclude_empty_fields: false}]});

  const all = (await api('GET', '/api/events/definitions?per_page=500')).event_definitions;
  if (!dry) {
    try { localStorage.setItem('defs_backup_' + new Date().toISOString().slice(0, 10), JSON.stringify(all)); }
    catch (e) { throw new Error('не удалось сохранить резервную копию: ' + e); }
  }
  const report = [];
  for (const [title, v] of Object.entries(SPEC)) {
    const d = all.find(x => x.title === title);
    if (!d) { report.push({определение: title, действие: 'не найдено'}); continue; }
    const fs = d.field_spec || {};
    const same = fs.mitre_tactic && fs.mitre_technique && fs.mitre_techniques &&
      fs.mitre_tactic.providers[0].template === v[0] &&
      fs.mitre_technique.providers[0].template === v[1] &&
      fs.mitre_techniques.providers[0].template === v[2];
    if (same) { report.push({определение: title, действие: 'без изменений'}); continue; }
    report.push({определение: title, действие: 'записать'});
    if (dry) continue;
    const body = JSON.parse(JSON.stringify(d));
    body.field_spec = Object.assign({}, fs, {mitre_tactic: mk(v[0]), mitre_technique: mk(v[1]), mitre_techniques: mk(v[2])});
    await api('PUT', '/api/events/definitions/' + d.id + '?schedule=true', body);
  }
  console.table(report);
  console.log(dry ? 'Пробный запуск: ничего не записано.' : 'Готово.');
  return report;
}
