#!/usr/bin/env python3
"""Собирает каталог детектов из detections-source.json.

    python3 build_catalog.py                 # читает detections-source.json рядом со скриптом
    python3 build_catalog.py my-source.json  # другой файл-источник

Результат:
  ../../docs/14-detections.md   страница каталога: матрица покрытия и таблицы по платформам
  catalog.csv                   то же в виде таблицы для Excel и скриптов

Источник данных получают скриптом export-catalog.js из живого Graylog (см. README.md рядом).
Ничего руками в docs/14-detections.md править не нужно: исправления вносятся в Graylog,
затем выгружается новый источник и запускается этот скрипт.
"""
import csv, json, os, re, sys
from collections import Counter, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'detections-source.json')
OUT_MD = os.path.join(HERE, '..', '..', 'docs', '14-detections.md')
OUT_CSV = os.path.join(HERE, 'catalog.csv')

TACTICS = ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
           'Stealth', 'Defense Impairment', 'Credential Access', 'Discovery', 'Lateral Movement',
           'Collection', 'Command and Control', 'Exfiltration', 'Impact']
TACTIC_RU = {'Reconnaissance': 'Разведка', 'Initial Access': 'Первоначальный доступ', 'Execution': 'Выполнение',
             'Persistence': 'Закрепление', 'Privilege Escalation': 'Повышение привилегий',
             'Stealth': 'Скрытность', 'Defense Impairment': 'Подавление защиты',
             'Credential Access': 'Доступ к учётным данным', 'Discovery': 'Исследование среды',
             'Lateral Movement': 'Перемещение', 'Collection': 'Сбор данных',
             'Command and Control': 'управление, C2', 'Exfiltration': 'Вывод данных', 'Impact': 'Воздействие'}

# платформы в порядке следования в документе: (ключ, заголовок, подсказка)
PLATFORMS = OrderedDict([
    ('windows', ('Windows', 'Sysmon, Security, PowerShell, Defender; поток WindowsLogs')),
    ('linux', ('Linux', 'auditd на RED OS; поток RedOS auditd Logs')),
    ('macos', ('macOS (osquery и unified log)', 'osquery Endpoint Security и unified log; поток MacOS Logs')),
    ('macos_bz', ('macOS (BI.ZONE Triage)', 'снимки состояния BI.ZONE Triage; поток BiZone_macOS')),
    ('keenetic', ('Keenetic', 'syslog роутера; поток Syslog Logs')),
    ('freeipa', ('FreeIPA и здоровье сервисов', 'аудит FreeIPA и служебные проверки')),
    ('containers', ('Контейнеры', 'Docker-логи через promtail и Filebeat; поток Containers')),
])
MATRIX_COLS = [('windows', 'Windows'), ('linux', 'Linux'), ('macos', 'macOS'), ('keenetic', 'Keenetic'),
               ('freeipa', 'FreeIPA'), ('containers', 'Контейнеры')]
PRIO = {1: 'низкий', 2: 'средний', 3: 'высокий'}


def platform(title):
    if title.startswith('Windows'): return 'windows'
    if title.startswith('LNX') or title.startswith('HEALTH'): return 'linux' if title.startswith('LNX') else 'freeipa'
    if title.startswith('macOS - Bi.Zone'): return 'macos_bz'
    if title.startswith('macOS'): return 'macos'
    if title.startswith('KEENETIC'): return 'keenetic'
    if title.startswith('FREEIPA'): return 'freeipa'
    if title.startswith('Контейнеры'): return 'containers'
    return 'other'


def matrix_col(p):
    return 'macos' if p == 'macos_bz' else p


def fmt_min(m):
    m = float(m)
    if m % 1440 == 0 and m >= 1440: return f'{int(m // 1440)} сут'
    if m % 60 == 0 and m >= 60: return f'{int(m // 60)} ч'
    return f'{int(m)} мин'


def correlation(d):
    parts = []
    c = d.get('condition')
    if d.get('aggregated') and c:
        op = {'>=': '≥', '>': '>', '<': '<', '<=': '≤', '=': '='}.get(c['op'], c['op'])
        v = c['value']
        v = int(v) if isinstance(v, (int, float)) and float(v).is_integer() else v
        gb = ', '.join(re.sub(r'^winlogbeat_winlog_event_data_', '', g) for g in (d.get('group_by') or []))
        s = f'число событий {op} {v} за {fmt_min(d["window_min"])}'
        if gb: s += f', группировка по {gb}'
        parts.append(s)
    elif d.get('aggregated'):
        parts.append(f'агрегация за {fmt_min(d["window_min"])}')
    else:
        parts.append('каждое событие')
    g = d.get('grace_min') or 0
    if g > 5: parts.append(f'повтор не чаще раза в {fmt_min(g)}')
    return '; '.join(parts)


def sources(d):
    """Короткое описание: какие события в логе проверяются (по ключевым полям запроса)."""
    q = d['query']
    found = []

    def add(label, rx, fmt=None):
        for m in re.finditer(rx, q):
            v = m.group(1).strip()
            v = re.sub(r'\s+OR\s+', ', ', v.strip('()'))
            v = v.replace('"', '')
            if len(v) > 46: v = v[:44] + '…'
            s = fmt.format(v) if fmt else f'{label} {v}'
            if s not in found: found.append(s)
    add('', r'audit_type:(\([^)]*\)|[\w]+)', 'auditd {}')
    add('', r'\bkey:(\([^)]*\)|[\w]+)', 'ключ {}')
    add('', r'\bname:(es_process_events|file_events|sudo_commands|listening_ports)', 'osquery {}')
    add('', r'log_type:(macos_unified|macos_wifi_usb)', 'журнал {}')
    add('', r'mac_bz_event_type:(\w+)', 'BI.ZONE {}')
    add('', r'win_channel:("[^"]+"|\w+)', 'канал {}')
    add('', r'win_event_id:(\([^)]*\)|\d+)', 'EventID {}')
    add('', r'winlogbeat_winlog_event_id:(\([^)]*\)|\d+)', 'EventID {}')
    add('', r'winlogbeat_event_code:(\([^)]*\)|\d+)', 'EventID {}')
    add('', r'kn_event_type:(\([^)]*\)|\w+)', 'событие Keenetic {}')
    add('', r'application_name:(\w+)', 'приложение {}')
    add('', r'container_name:("[^"]+"|\w+)', 'контейнер {}')
    return ', '.join(found[:4])


def esc(s):
    return s.replace('|', '\\|').replace('\n', ' ')


def stream_of(d):
    return ', '.join(d['streams']) if d['streams'] else '—'


defs = json.load(open(SRC, encoding='utf-8'))['definitions']
for d in defs:
    d['platform'] = platform(d['title'])
    d['corr'] = correlation(d)
    d['log'] = sources(d)
defs = [d for d in defs if d['platform'] != 'other']
by = {k: sorted([d for d in defs if d['platform'] == k], key=lambda x: (-x['priority'], x['title'])) for k in PLATFORMS}

# ---------- CSV ----------
with open(OUT_CSV, 'w', newline='', encoding='utf-8') as f:
    w = csv.writer(f)
    w.writerow(['Платформа', 'Правило', 'Приоритет', 'Поток', 'Источник логов', 'Что проверяет', 'Корреляция',
                'Тактика', 'Техника', 'Все техники', 'Уведомление', 'Запрос (очищенный)'])
    for k in PLATFORMS:
        for d in by[k]:
            w.writerow([PLATFORMS[k][0], d['title'], PRIO[d['priority']], stream_of(d), d['log'], d['description'],
                        d['corr'], d['tactic'] or '', d['technique'] or '', d['techniques'] or '',
                        ', '.join(d['notifications']), d['query']])

# ---------- Markdown ----------
L = []
w = L.append
total = len(defs)
with_tech = sum(1 for d in defs if d['tactic'])
techs = set()
for d in defs:
    for t in (d['techniques'] or '').split(','):
        t = t.strip()
        if t: techs.add(t)
w('# Каталог детектов Graylog')
w('')
w(f'> Все правила (event definitions) лаборатории в одном месте: какой лог проверяется, по какому условию, '
  f'как коррелируются события, к какой тактике и технике MITRE ATT&CK относятся. '
  f'Всего **{total}** правил, из них **{with_tech}** привязаны к технике ATT&CK v20 '
  f'({len(techs)} разных техник). Остальные описывают здоровье сервисов и тишину в логах: атак они не ловят.')
w('')
w('Страница собирается скриптом из выгрузки Graylog и руками не правится: '
  '[как обновить](#как-обновить-каталог). Запросы очищены: IP, MAC, отпечатки ключей и белые списки '
  'заменены на `<IP>`, `<MAC>`, `<белый список>`. Готовые определения для импорта лежат в '
  '`graylog/*-event-definitions.json`, соответствие техникам подробно описано в [graylog/mitre](../graylog/mitre/README.md).')
w('')
w('## Содержание')
w('')
w('- [Покрытие: тактики × платформы](#покрытие-тактики--платформы)')
for k, (title, hint) in PLATFORMS.items():
    anchor = None
    w(f'- [{title}](#{re.sub(r"[^0-9a-zа-яё ]", "", title.lower()).replace(" ", "-")}) — {len(by[k])}')
w('- [Как читать таблицы](#как-читать-таблицы)')
w('- [Как обновить каталог](#как-обновить-каталог)')
w('')
w('## Покрытие: тактики × платформы')
w('')
w('Основная тактика правила — первая из записанных в событии (поле `mitre_tactic`). '
  'Пустая ячейка означает, что правил на эту тактику на платформе нет.')
w('')
w('| Тактика | ' + ' | '.join(n for _, n in MATRIX_COLS) + ' | Всего |')
w('|---|' + '---|' * len(MATRIX_COLS) + '---|')
cnt = Counter((d['tactic'] or '—', matrix_col(d['platform'])) for d in defs)
colsum = Counter()
for t in TACTICS + ['—']:
    row = [cnt.get((t, c), 0) for c, _ in MATRIX_COLS]
    if not sum(row): continue
    for (c, _), v in zip(MATRIX_COLS, row): colsum[c] += v
    name = f'{t} ({TACTIC_RU[t]})' if t in TACTIC_RU else 'Без техники (служебные)'
    w(f'| {name} | ' + ' | '.join(str(v) if v else '' for v in row) + f' | **{sum(row)}** |')
w('| **Всего** | ' + ' | '.join(f'**{colsum[c]}**' for c, _ in MATRIX_COLS) + f' | **{total}** |')
w('')
missing = [t for t in TACTICS if not any(cnt.get((t, c)) for c, _ in MATRIX_COLS)]
if missing:
    w('Тактики без единого правила: ' + ', '.join(f'{t} ({TACTIC_RU[t]})' for t in missing) + '.')
    w('')

for k, (title, hint) in PLATFORMS.items():
    rows = by[k]
    if not rows: continue
    w(f'## {title}')
    w('')
    w(f'{hint}. Правил: {len(rows)}. Сортировка: сначала высокий приоритет.')
    w('')
    w('| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |')
    w('|---|---|---|---|---|---|---|')
    for d in rows:
        name = d['title'].split(' - ', 1)[-1] if ' - ' in d['title'] else d['title']
        tech = (d['technique'] or '—')
        extra = [t.strip() for t in (d['techniques'] or '').split(',') if t.strip()]
        main_id = (d['technique'] or '').split(' ')[0]
        more = [t for t in extra if t != main_id]
        if more: tech += '<br>' + ', '.join(f'`{t}`' for t in more)
        if d['technique']:
            tid, _, tname = d['technique'].partition(' ')
            tech = f'`{tid}` {tname}' + (('<br>' + ', '.join(f'`{t}`' for t in more)) if more else '')
        desc = d['description'].split('\n')[0]
        if len(desc) > 190: desc = desc[:187].rsplit(' ', 1)[0] + '…'
        w(f'| {esc(name)} | {PRIO[d["priority"]]} | {esc(stream_of(d))}{("<br>" + esc(d["log"])) if d["log"] else ""} | {esc(desc)} | '
          f'{esc(d["corr"])} | {d["tactic"] or "—"} | {tech} |')
    w('')
    w('<details><summary>Запросы Graylog (очищенные)</summary>')
    w('')
    for d in rows:
        w(f'**{d["title"]}**')
        w('')
        w('```')
        w(d['query'])
        w('```')
        w('')
    w('</details>')
    w('')

w('## Как читать таблицы')
w('')
w('| Колонка | Смысл |')
w('|---|---|')
w('| Приоритет | Приоритет события в Graylog: высокий (3), средний (2), низкий (1). Низкие чаще уходят сводкой, а не отдельным письмом |')
w('| Источник логов | Поток Graylog и ключевые поля запроса: тип записи auditd, `EventID`, имя таблицы osquery, тип события Keenetic и т. п. |')
w('| Что проверяет | Первое предложение описания правила |')
w('| Корреляция | «каждое событие» — алерт на любое совпадение. «число событий ≥ N за M мин» — агрегация с порогом и группировкой. «повтор не чаще раза в …» — пауза (grace period), в течение которой одно и то же событие повторно не отправляется |')
w('| Тактика, техника | MITRE ATT&CK v20 (Enterprise). В ячейке «Техника» первой стоит основная, ниже через запятую дополнительные |')
w('')
w('Проверка приблизительна там, где в [таблице соответствий](../graylog/mitre/attack-mapping.md) '
  'стоит «низкая» уверенность: такие привязки стоит перепроверять.')
w('')
w('## Как обновить каталог')
w('')
w('1. Откройте Graylog в браузере (залогиньтесь), F12 → Console, вставьте '
  '[`graylog/detections/export-catalog.js`](../graylog/detections/export-catalog.js) целиком и выполните '
  '`await exportCatalog()`. Браузер скачает `detections-source.json`: очищенные определения без IP, MAC и белых списков.')
w('2. Положите файл в `graylog/detections/` вместо старого.')
w('3. Запустите `python3 graylog/detections/build_catalog.py`: обновятся эта страница и `graylog/detections/catalog.csv`.')
w('')
w('Новое правило появится в каталоге само, как только оно создано в Graylog; тактика и техника берутся из полей '
  '`mitre_tactic`, `mitre_technique`, `mitre_techniques` в определении (см. [graylog/mitre](../graylog/mitre/README.md)).')
w('')

os.makedirs(os.path.dirname(OUT_MD), exist_ok=True)
open(OUT_MD, 'w', encoding='utf-8').write('\n'.join(L))
print('ok', total, 'правил;', OUT_MD, OUT_CSV)
