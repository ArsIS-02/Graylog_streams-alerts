/*
 * Импорт дашбордов из dashboards-spec.json в Graylog 7.x.
 * Запуск: открой Graylog в браузере (залогинься), F12 → Console, вставь файл целиком,
 * затем:  await importDashboards(SPEC, {dryRun: true})   // только показать, что будет создано
 *         await importDashboards(SPEC)                    // создать
 * SPEC — содержимое dashboards-spec.json (вставь как: const SPEC = [...]; ).
 * Потоки находятся по названию, поэтому названия потоков должны совпадать с теми, что в spec.
 */
async function importDashboards(SPEC, opts = {}) {
  const H = {'Content-Type': 'application/json', 'X-Requested-By': 'XMLHttpRequest'};
  const api = async (m, u, b) => {
    const r = await fetch(u, {method: m, headers: H, credentials: 'same-origin', body: b ? JSON.stringify(b) : undefined});
    if (!r.ok) throw new Error(m + ' ' + u + ' → ' + r.status + ' ' + (await r.text()));
    return r.json();
  };
  const uuid = () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0; return (c === 'x' ? r : (r & 3 | 8)).toString(16);
  });
  const streams = (await api('GET', '/api/streams')).streams;
  const sid = t => { const s = streams.find(s => s.title === t); if (!s) throw new Error('Нет потока: ' + t); return s.id; };

  const pivot = ([kind, field, p], forType) => {
    if (kind === 't') {
      let interval = {type: 'auto', scaling: 1};
      if (p !== 'auto') {
        const m = /^(\d+)(minutes|hours|days)$/.exec(p);
        const short = {minutes: 'm', hours: 'h', days: 'd'}[m[2]];
        interval = forType ? {type: 'timeunit', timeunit: m[1] + short}
                           : {type: 'timeunit', value: +m[1], unit: m[2]};
      }
      return {type: 'time', fields: [field], config: {interval}};
    }
    return {type: 'values', fields: [field], config: {limit: p}};
  };
  const fn = f => { const m = /^(\w+)\((.*)\)$/.exec(f); return {type: m[1], id: f, field: m[2] || null}; };
  const sorts = (arr, ser) => (arr || []).map(s => {
    const [f, dir] = s.split(' ');
    return ser.includes(f) ? {type: 'series', field: f, direction: dir} : {type: 'pivot', field: f, direction: dir};
  });

  const result = [];
  for (const D of SPEC) {
    const queries = [], state = {};
    for (const P of D.pages) {
    const qid = uuid(), widgets = [], mapping = {}, positions = {}, titles = {}, types = [];
    for (const W of P.widgets) {
      const id = uuid();
      const sids = (W.s || []).map(sid);
      const base = {id, type: W.v === 'messages' ? 'messages' : (W.v === 'text' ? 'text' : 'aggregation'),
        filter: null, timerange: {type: 'relative', range: W.r || P.timerange},
        query: {type: 'elasticsearch', query_string: W.q || ''}, streams: sids, stream_categories: []};
      positions[id] = {col: W.pos[0], row: W.pos[1], height: W.h, width: W.w};
      titles[id] = W.t;
      if (W.v === 'text') {
        widgets.push({...base, config: {text: W.txt || ''}, timerange: undefined, query: undefined, streams: undefined});
        continue;
      }
      const stId = uuid(); mapping[id] = [stId];
      if (W.v === 'messages') {
        widgets.push({...base, config: {fields: W.f, show_message_row: true, show_summary: false,
          decorators: [], sort: [{field: 'timestamp', direction: 'DESC'}], sortDirection: 'DESC'}});
        types.push({type: 'messages', id: stId, limit: W.lim || 100, offset: 0, sort: [{field: 'timestamp', order: 'DESC'}],
          decorators: [], streams: sids, timerange: base.timerange, query: base.query, filter: null});
        continue;
      }
      const ser = (W.m || ['count()']);
      const vc = W.v === 'bar' || W.v === 'area' || W.v === 'line'
        ? {barmode: W.bm || 'group', axis_type: 'linear'} : {};
      widgets.push({...base, config: {visualization: W.v, visualization_config: Object.keys(vc).length ? vc : null,
        series: ser.map(f => ({config: {name: null}, function: f})), row_pivots: (W.rows || []).map(p => pivot(p, false)),
        column_pivots: (W.cols || []).map(p => pivot(p, false)), sort: sorts(W.sort, ser), rollup: true, event_annotation: false}});
      types.push({type: 'pivot', id: stId, name: 'chart', streams: sids, timerange: base.timerange, query: base.query, filter: null,
        series: ser.map(fn), row_groups: (W.rows || []).map(p => pivot(p, true)),
        column_groups: (W.cols || []).map(p => pivot(p, true)), sort: sorts(W.sort, ser), rollup: true,
        filters: [], event_annotation: false});
    }
    queries.push({id: qid, query: {type: 'elasticsearch', query_string: ''},
      timerange: {type: 'relative', range: P.timerange}, search_types: types});
    state[qid] = {selected_fields: null, static_message_list_id: null,
      titles: {widget: titles, tab: {title: P.title || 'Страница'}}, widgets, widget_mapping: mapping,
      positions, formatting: {highlighting: []}};
    }
    const search = {queries, parameters: []};
    const view = {type: 'DASHBOARD', title: D.title, summary: D.summary, description: D.description, properties: [], requires: {}, state};
    if (opts.dryRun) { result.push({title: D.title, pages: D.pages.length, search, view}); continue; }
    const s = await api('POST', '/api/views/search', search);
    view.search_id = s.id;
    const v = await api('POST', '/api/views', {entity: view});
    result.push({title: D.title, id: v.id});
  }
  return result;
}
