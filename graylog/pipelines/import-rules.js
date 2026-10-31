/*
 * Импорт правил pipeline из rules.json в Graylog 7.x.
 * Запуск: открой Graylog в браузере (залогинься), F12 → Console, вставь файл целиком,
 * затем:  const SPEC = [...];                                  // содержимое rules.json
 *         await importRules(SPEC, {dryRun: true})              // только показать, что изменится
 *         await importRules(SPEC)                              // создать и обновить
 *
 * Если Graylog открыт не с корня (например https://host/graylog/), укажи префикс:
 *         await importRules(SPEC, {base: '/graylog'})
 *
 * Скрипт трогает только правила (rule), найденные по названию. Сами pipeline и их стадии он
 * не меняет: запись pipeline через API заменяет его целиком и стирает стадии, которых нет в
 * теле запроса. Подключение правил к стадиям делается в интерфейсе (см. README.md).
 */
async function importRules(SPEC, opts = {}) {
  const base = (opts.base || '').replace(/\/$/, '');
  const dry = !!opts.dryRun;
  const H = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Requested-By': 'XMLHttpRequest'};
  const api = async (method, path, body) => {
    const r = await fetch(base + path, {method, headers: H, credentials: 'same-origin',
      body: body ? JSON.stringify(body) : undefined});
    if (!r.ok) throw new Error(method + ' ' + path + ' → ' + r.status + ' ' + (await r.text()));
    return r.json();
  };

  const existing = await api('GET', '/api/system/pipelines/rule');
  const report = [];
  for (const rule of SPEC) {
    const body = {title: rule.title, description: rule.description || '', source: rule.source};
    const cur = existing.find(e => e.title === rule.title);
    let action;
    if (!cur) {
      action = 'создать';
      if (!dry) await api('POST', '/api/system/pipelines/rule', body);
    } else if ((cur.source || '').trim() === body.source.trim() && (cur.description || '') === body.description) {
      action = 'без изменений';
    } else {
      action = 'обновить';
      if (!dry) await api('PUT', '/api/system/pipelines/rule/' + cur.id, body);
    }
    report.push({правило: rule.title, действие: action});
  }
  console.table(report);
  console.log(dry ? 'Пробный запуск: ничего не записано.' : 'Готово. Подключи правила к стадиям pipeline (README.md).');
  return report;
}
