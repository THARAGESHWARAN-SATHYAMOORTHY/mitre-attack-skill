---
name: "mitre-attack"
description: "Use for any MITRE ATT&CK work: map incidents/reports to TTPs, validate IDs, detection coverage and gaps, Navigator layers, group profiling, emulation plans, Sigma/Atomic mapping, version migration."
---

# MITRE ATT&CK skill

Baseline: **ATT&CK v20.1** (v20 released 2026-10-13; v20.1 data patch modified 2026-11-05). Facts and the tool below were checked against live STIX data on **2026-11-14**. When live data disagrees with this text (a newer ATT&CK release), trust the live data. ATT&CK ships major releases in April and October plus smaller "Agile" releases (groups/software/campaigns) in between (first: v19.2, Aug 2026).

## Hard rules

1. **State the ATT&CK version** (and domain) in every deliverable. Get it from `attack.py version`.
2. **Verify every ID and name against live data** before output (`get`, or `validate` on the finished draft). Never quote IDs from memory.
3. **Never invent behavior.** Every mapping cites evidence (quote, log line, report page). No evidence, no mapping; inference is marked Low confidence with the reason.
4. **Redact before output.** Strip secrets, API keys, tokens, passwords, hashes of credentials, PII, salary data, and card numbers from any log, ticket, or connector data before it goes into a table, layer comment, or report. Use `[REDACTED-<type>]`.
5. **No weaponization.** Atomic Red Team output is test names, GUIDs, platforms, and executor type only. Do not write exploit code, payloads, or step-by-step attack commands. Emulation plans reference test IDs and are for authorized scope only.
6. Use the most specific sub-technique the evidence supports; otherwise the parent.
7. Enterprise content that says "Defense Evasion" or "14 tactics" is pre-v19: migrate it (workflow E).

## 0. Install the tool and load data (always first)

One stdlib-only CLI. Install by running this block once per workspace (it writes `~/attack_tools/attack.py`):

```bash
mkdir -p ~/attack_tools ~/attack-data && cat > ~/attack_tools/attack.py <<'PYEOF'
#!/usr/bin/env python3
"""attack.py - stdlib-only MITRE ATT&CK CLI (enterprise / mobile / ics). Run: python3 -I attack.py <command> -h"""
import argparse, csv, io, json, os, re, subprocess, sys, time, urllib.error, urllib.request
from collections import Counter, defaultdict

DATA = os.path.expanduser(os.environ.get('ATTACK_DATA', '~/attack-data'))
DOMAINS = ('enterprise', 'mobile', 'ics')
STIX = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{d}-attack/{d}-attack{v}.json'
ART = 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/'
NAV = {'navigator': '5.3.2', 'layer': '4.5'}  # attack-navigator nav-app/package.json + layers/spec (checked 2026-11-14)
SRC = ('mitre-attack', 'mitre-mobile-attack', 'mitre-ics-attack')
KIND = {'attack-pattern': 'technique', 'x-mitre-tactic': 'tactic', 'intrusion-set': 'group', 'malware': 'software',
        'tool': 'software', 'campaign': 'campaign', 'course-of-action': 'mitigation',
        'x-mitre-detection-strategy': 'detection-strategy', 'x-mitre-analytic': 'analytic',
        'x-mitre-data-component': 'data-component', 'x-mitre-asset': 'asset'}
ID_RE = re.compile(r'(?<![A-Za-z0-9])(attack\.)?(TA\d{4}|T\d{4}(?:\.\d{3})?|DET\d{4}|AN\d{4}|DC\d{4}|[GSCMA]\d{4})(?![\dA-Za-z])', re.I)
TID_RE = re.compile(r'(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?(?![\dA-Za-z])', re.I)
STATUS = {'none': 0, 'logs': 1, 'rule': 2, 'tested': 3}
COLORS = ['#ff6666', '#ffd966', '#9fc5e8', '#6aa84f']

def die(m): print('error: ' + m, file=sys.stderr); sys.exit(2)
def warn(m): print('warning: ' + m, file=sys.stderr)
def dead(o): return bool(o.get('revoked') or o.get('x_mitre_deprecated'))
def eid(o): return next((r['external_id'] for r in o.get('external_references', []) if r.get('source_name') in SRC and r.get('external_id')), None)
def aliases(o): return [a for a in (o.get('aliases') or o.get('x_mitre_aliases') or []) if a != o.get('name')]
def state(o): return 'REVOKED' if o.get('revoked') else 'DEPRECATED' if o.get('x_mitre_deprecated') else 'active'
def clean(t, n=0):
    t = re.sub(r'\(Citation:[^)]*\)', '', t or ''); t = re.sub(r'</?code>', '`', t)
    t = re.sub(r'\s+', ' ', re.sub(r'\[([^\]]+)\]\(https?://[^)]+\)', r'\1', t)).strip()
    return t if not n or len(t) <= n else t[:n].rsplit(' ', 1)[0] + ' ...'

def fetch(url, timeout=180):
    """GET url -> bytes, or None on 404. urllib first, curl fallback (proxy / CA quirks)."""
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'attack-cli'}), timeout=timeout) as r: return r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404: return None
    except Exception: pass
    p = subprocess.run(['curl', '-sSLf', '--max-time', str(timeout), url], capture_output=True)
    if p.returncode == 22: return None
    if p.returncode: die(f'download failed: {url}: {p.stderr.decode(errors="replace").strip()}')
    return p.stdout

def cached(url, ttl=86400):
    p = os.path.join(DATA, 'cache', re.sub(r'[^A-Za-z0-9.]+', '_', url.split('://')[1])[-150:])
    if not (os.path.exists(p) and time.time() - os.path.getmtime(p) < ttl):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'wb') as f: f.write(fetch(url, 60) or b'')
    with open(p, encoding='utf-8', errors='replace') as f: return f.read()

class KB:
    def __init__(s, dom, path=None):
        s.dom, s.path = dom, path or os.path.join(DATA, dom + '.json')
        if not os.path.exists(s.path): die(f'missing {s.path} - run: attack.py update')
        with open(s.path, encoding='utf-8') as f: objs = json.load(f).get('objects', [])
        s.by, s.ids, s.col, mats = {}, defaultdict(list), {}, []
        s.out, s.inn = defaultdict(lambda: defaultdict(list)), defaultdict(lambda: defaultdict(list))
        for o in objs:
            t = o.get('type')
            if t == 'x-mitre-collection': s.col = o
            elif t == 'x-mitre-matrix': mats.append(o)
            elif t == 'relationship':
                if not dead(o):
                    s.out[o['relationship_type']][o['source_ref']].append(o['target_ref'])
                    s.inn[o['relationship_type']][o['target_ref']].append(o['source_ref'])
            elif t in KIND and eid(o): s.by[o['id']] = o; s.ids[eid(o).upper()].append(o)
        for v in s.ids.values(): v.sort(key=dead)
        s.ver = s.col.get('x_mitre_version', '?')
        order = [r for m in sorted(mats, key=dead) for r in m.get('tactic_refs', [])]
        s.tactics = [s.by[r] for r in dict.fromkeys(order) if r in s.by and not dead(s.by[r])]
        s.short = {t['x_mitre_shortname']: t for t in s.tactics}
        s._gm = None
    def one(s, i):
        v = s.ids.get(str(i).strip().upper()); return v[0] if v else None
    def all(s, kind, alive=True): return [o for o in s.by.values() if KIND[o['type']] == kind and not (alive and dead(o))]
    def rel(s, o, rt, rev=False, kinds=None, alive=True):
        r = [s.by[x] for x in dict.fromkeys((s.inn if rev else s.out)[rt].get(o['id'], [])) if x in s.by]
        return sorted([x for x in r if not (alive and dead(x)) and (not kinds or KIND[x['type']] in kinds)], key=eid)
    def tname(s, o):
        par = s.rel(o, 'subtechnique-of', alive=False) if o.get('x_mitre_is_subtechnique') else []
        return (par[0]['name'] + ': ' if par else '') + o['name']
    def tacs(s, o):
        ph = {p['phase_name'] for p in o.get('kill_chain_phases', [])}; return [n for n in s.short if n in ph]
    def chain(s, o):
        out, seen = [], set()
        while o.get('revoked') and o['id'] not in seen:
            seen.add(o['id']); nxt = s.rel(o, 'revoked-by', alive=False)
            if not nxt: break
            o = nxt[0]; out.append(o)
        return out
    def find(s, q, kinds=None):
        ql = q.strip().lower(); pool = [o for o in s.by.values() if not kinds or KIND[o['type']] in kinds]
        tests = (lambda o: eid(o).lower() == ql, lambda o: o.get('name', '').lower() == ql,
                 lambda o: ql in [a.lower() for a in aliases(o)],
                 lambda o: ql in o.get('name', '').lower() or any(ql in a.lower() for a in aliases(o)))
        for t in tests:
            hit = [o for o in pool if t(o)]
            if hit: return sorted(hit, key=lambda o: (dead(o), len(o.get('name', '')), eid(o)))
        return []
    def used(s, o, with_software=False):
        """Techniques used by a group/software/campaign -> {technique_id: [via, ...]} (groups include attributed campaigns)."""
        res, srcs = defaultdict(list), [(o, 'direct')]
        if o['type'] == 'intrusion-set': srcs += [(c, eid(c)) for c in s.rel(o, 'attributed-to', rev=True)]
        if with_software: srcs += [(x, eid(x)) for src, _ in list(srcs) for x in s.rel(src, 'uses', kinds=('software',))]
        for src, via in srcs:
            for t in s.rel(src, 'uses', kinds=('technique',)):
                if via not in res[eid(t)]: res[eid(t)].append(via)
        return res
    def groupmap(s):
        """technique_id -> sorted group IDs (direct use or via attributed campaign)."""
        if s._gm is None:
            s._gm = defaultdict(set)
            for g in s.all('group'):
                for t in s.used(g): s._gm[t].add(eid(g))
        return s._gm

_kb = {}
def kb(dom):
    if dom not in _kb: _kb[dom] = KB(dom)
    return _kb[dom]
def doms(a): return DOMAINS if a.domain in ('auto', 'all') else (a.domain,)
def lookup(a, q, kinds=None):
    """-> (KB, [objects], other domains holding the same ID). First domain with a hit wins."""
    hit = [(kb(d), kb(d).find(q, kinds)) for d in doms(a)]
    hit = [h for h in hit if h[1]]
    if not hit: die(f'no ATT&CK object matches {q!r}' + (f' of type {"/".join(kinds)}' if kinds else '') + ' - try: attack.py search ' + json.dumps(q))
    k, objs = sorted(hit, key=lambda h: dead(h[1][0]))[0]
    return k, objs, [h[0].dom for h in hit if h[0] is not k and any(eid(x) == eid(objs[0]) for x in h[1])]
def pick_domain(a, ids):
    if a.domain not in ('auto', 'all'): return kb(a.domain)
    n = {d: sum(1 for i in ids if kb(d).one(i)) for d in DOMAINS}
    return kb(max(DOMAINS, key=lambda d: n[d]))

# ---------- output ----------
def tbl(rows, cols=None, limit=0):
    if not rows: return '_none_\n'
    cols = cols or list(rows[0]); f = lambda c: ('; '.join(map(str, c)) if isinstance(c, list) else str(c if c is not None else '')).replace('|', '/').replace('\n', ' ')
    body = ['| ' + ' | '.join(f(r.get(c)) for c in cols) + ' |' for r in (rows[:limit] if limit else rows)]
    more = [f'_... {len(rows) - limit} more (use --limit 0 or --json)_'] if limit and len(rows) > limit else []
    return '\n'.join(['| ' + ' | '.join(cols) + ' |', '|' + '---|' * len(cols)] + body + more) + '\n'
def emit(a, d):
    if a.json: print(json.dumps(d, indent=2, ensure_ascii=False)); return
    print(f"## {d.pop('title', '')}\n"); tables = []
    for k, v in d.items():
        if v in (None, '', [], {}) or k in ('id', 'name', 'type'): continue
        if isinstance(v, list) and isinstance(v[0], dict): tables.append((k, v))
        elif isinstance(v, list) and sum(len(str(x)) for x in v) > 160: print(f'- **{k.replace("_", " ")}:**\n' + '\n'.join(f'  - {x}' for x in v))
        else: print(f'- **{k.replace("_", " ")}:** ' + (', '.join(map(str, v)) if isinstance(v, list) else str(v)))
    for k, v in tables: print(f'\n### {k.replace("_", " ")} ({len(v)})\n\n' + tbl(v, limit=a.limit), end='')

def refs(k, xs, **extra): return [dict(id=eid(x), name=x['name'], **{n: f(x) for n, f in extra.items()}) for x in xs]
def trefs(k, xs): return [dict(id=eid(t), name=k.tname(t), tactics=', '.join(k.tacs(t))) for t in xs]

def describe(k, o, a, also=()):
    K = KIND[o['type']]; url = next((r.get('url') for r in o['external_references'] if r.get('source_name') in SRC), '')
    d = {'title': f"{eid(o)} {o['name']} [{K}]", 'id': eid(o), 'name': o['name'], 'type': K, 'stix_type': o['type'], 'domain': k.dom + '-attack',
         'also_in_domains': list(also), 'attack_version': k.ver, 'status': state(o), 'object_version': o.get('x_mitre_version'),
         'created': o.get('created', '')[:10], 'modified': o.get('modified', '')[:10], 'url': url}
    if o.get('revoked'):
        ch = k.chain(o); d['replaced_by'] = ' -> '.join(f"{eid(x)} {x['name']} ({state(x)})" for x in ch) or 'no revoked-by target in data'
        if ch: d['note'] = f"Use {eid(ch[-1])} instead; run `get {eid(ch[-1])}` for current detail."
    elif o.get('x_mitre_deprecated'): d['note'] = 'Deprecated: removed from ATT&CK without a direct replacement. Re-map from the original evidence.'
    d['supersedes'] = [f"{eid(x)} {x['name']}" for x in k.rel(o, 'revoked-by', rev=True, alive=False)]
    d['aliases'] = aliases(o)
    d['description'] = clean(o.get('description'), 0 if a.full else 700)
    if K == 'technique':
        par = k.rel(o, 'subtechnique-of', alive=False)
        d.update(tactics=[f"{k.short[t]['name']} ({eid(k.short[t])}, {t})" for t in k.tacs(o)], platforms=o.get('x_mitre_platforms', []),
                 parent=f"{eid(par[0])} {par[0]['name']}" if par else None, subtechniques=refs(k, k.rel(o, 'subtechnique-of', rev=True)),
                 mitigations=refs(k, k.rel(o, 'mitigates', rev=True)))
        det = []
        for ds in k.rel(o, 'detects', rev=True):
            for an in [k.by[r] for r in ds.get('x_mitre_analytic_refs', []) if r in k.by and not dead(k.by[r])]:
                ls = an.get('x_mitre_log_source_references', [])
                dcs = dict.fromkeys(f"{eid(k.by[l['x_mitre_data_component_ref']])} {k.by[l['x_mitre_data_component_ref']]['name']}" for l in ls if l.get('x_mitre_data_component_ref') in k.by)
                det.append({'strategy': f"{eid(ds)} {ds['name']}", 'analytic': eid(an), 'platforms': an.get('x_mitre_platforms', []), 'data_components': list(dcs),
                            'log_sources': list(dict.fromkeys(l.get('name', '') for l in ls)), 'logic': clean(an.get('description'), 0 if a.full else 160)})
        d.update(detection=det, groups=refs(k, k.rel(o, 'uses', rev=True, kinds=('group',))), software=refs(k, k.rel(o, 'uses', rev=True, kinds=('software',))),
                 campaigns=refs(k, k.rel(o, 'uses', rev=True, kinds=('campaign',))), targeted_assets=refs(k, k.rel(o, 'targets')))
    elif K == 'tactic':
        d['shortname'] = o.get('x_mitre_shortname')
        ts = [t for t in k.all('technique') if o.get('x_mitre_shortname') in k.tacs(t)]
        d['techniques'] = refs(k, sorted([t for t in ts if not t.get('x_mitre_is_subtechnique')], key=eid), subtechniques=lambda t: sum(1 for x in k.rel(t, 'subtechnique-of', rev=True)))
        d['total_including_subtechniques'] = len(ts)
    elif K in ('group', 'software', 'campaign'):
        u = k.used(o)
        d['techniques'] = [dict(id=i, name=k.tname(k.one(i)), tactics=', '.join(k.tacs(k.one(i))), via=', '.join(v)) for i, v in sorted(u.items(), key=lambda x: (min([list(k.short).index(t) for t in k.tacs(k.one(x[0]))] or [99]), x[0]))]
        if K == 'software': d.update(software_type=o['type'], platforms=o.get('x_mitre_platforms', []), used_by_groups=refs(k, k.rel(o, 'uses', rev=True, kinds=('group',))), used_in_campaigns=refs(k, k.rel(o, 'uses', rev=True, kinds=('campaign',))))
        else: d['software'] = refs(k, k.rel(o, 'uses', kinds=('software',)), type=lambda x: x['type'])
        if K == 'group': d['campaigns'] = refs(k, k.rel(o, 'attributed-to', rev=True))
        if K == 'campaign': d.update(first_seen=o.get('first_seen', '')[:10], last_seen=o.get('last_seen', '')[:10], attributed_to=refs(k, k.rel(o, 'attributed-to')))
    elif K == 'mitigation': d['techniques_mitigated'] = trefs(k, k.rel(o, 'mitigates', kinds=('technique',)))
    elif K == 'detection-strategy':
        d['detects'] = trefs(k, k.rel(o, 'detects'))
        d['analytics'] = [dict(id=eid(x), platforms=x.get('x_mitre_platforms', []), logic=clean(x.get('description'), 0 if a.full else 200)) for x in (k.by.get(r) for r in o.get('x_mitre_analytic_refs', [])) if x]
    elif K == 'analytic':
        d['platforms'] = o.get('x_mitre_platforms', [])
        d['strategy'] = [f"{eid(x)} {x['name']} -> " + ', '.join(eid(t) for t in k.rel(x, 'detects')) for x in k.all('detection-strategy') if o['id'] in x.get('x_mitre_analytic_refs', [])]
        d['log_sources'] = [dict(data_component=(lambda c: f"{eid(c)} {c['name']}" if c else '')(k.by.get(l.get('x_mitre_data_component_ref'))), name=l.get('name'), channel=l.get('channel')) for l in o.get('x_mitre_log_source_references', [])]
        d['tunables'] = [dict(field=m.get('field'), description=m.get('description')) for m in o.get('x_mitre_mutable_elements', [])]
    elif K == 'data-component':
        ans = {x['id'] for x in k.all('analytic') if any(l.get('x_mitre_data_component_ref') == o['id'] for l in x.get('x_mitre_log_source_references', []))}
        ts = {eid(t): t for x in k.all('detection-strategy') if ans & set(x.get('x_mitre_analytic_refs', [])) for t in k.rel(x, 'detects')}
        d.update(analytics_using=len(ans), log_sources=[dict(name=l.get('name'), channel=l.get('channel')) for l in o.get('x_mitre_log_sources', [])], techniques_detectable=trefs(k, [ts[i] for i in sorted(ts)]))
    elif K == 'asset': d.update(sectors=o.get('x_mitre_sectors', []), platforms=o.get('x_mitre_platforms', []), techniques_targeting=trefs(k, k.rel(o, 'targets', rev=True)))
    return d

# ---------- commands ----------
def c_update(a):
    os.makedirs(DATA, exist_ok=True); rows = []
    for d in doms(a):
        p = os.path.join(DATA, f'{d}-{a.release}.json' if a.release else f'{d}.json')
        fresh = os.path.exists(p) and (a.release or time.time() - os.path.getmtime(p) < 86400)
        act = 'fresh (<24h), skipped' if fresh else 'downloaded'
        if a.force or not fresh:
            b = fetch(STIX.format(d=d, v='-' + a.release if a.release else ''))
            if b is None: die(f'{d}-attack {a.release or "latest"} not found (see index.json in mitre-attack/attack-stix-data for versions)')
            json.loads(b)
            with open(p + '.tmp', 'wb') as f: f.write(b)
            os.replace(p + '.tmp', p); act = 'downloaded'
        k = KB(d, p); rows.append(dict(domain=d, version=k.ver, modified=k.col.get('modified', '')[:10], file=p, action=act))
    emit(a, {'title': 'ATT&CK data update', 'bundles': rows})

def c_version(a):
    rows = []
    for d in doms(a):
        k = kb(d); rows.append(dict(domain=d + '-attack', version=k.ver, modified=k.col.get('modified', '')[:10], spec=k.col.get('x_mitre_attack_spec_version'),
                                    file=k.path, age_hours=round((time.time() - os.path.getmtime(k.path)) / 3600, 1)))
    emit(a, {'title': 'ATT&CK data version', 'bundles': rows, 'navigator': NAV['navigator'], 'layer_format': NAV['layer']})

def c_stats(a):
    rows = []
    for d in doms(a):
        k = kb(d); c = Counter(KIND[o['type']] for o in k.by.values() if not dead(o)); t = k.all('technique')
        rows.append({'domain': d, 'version': k.ver, 'tactics': len(k.tactics), 'techniques': sum(1 for x in t if not x.get('x_mitre_is_subtechnique')),
                     'subtechniques': sum(1 for x in t if x.get('x_mitre_is_subtechnique')), 'groups': c['group'], 'software': c['software'], 'campaigns': c['campaign'],
                     'mitigations': c['mitigation'], 'DET': c['detection-strategy'], 'AN': c['analytic'], 'DC': c['data-component'], 'assets': c['asset'],
                     'revoked_or_deprecated': sum(1 for o in k.by.values() if dead(o))})
    emit(a, {'title': 'ATT&CK object counts (active objects only)', 'counts': rows})

def c_get(a, kinds=None):
    k, objs, also = lookup(a, a.query, kinds)
    d = describe(k, objs[0], a, also)
    if len(objs) > 1: d['other_matches'] = [f"{eid(x)} {x['name']} [{KIND[x['type']]}, {state(x)}]" for x in objs[1:15]]
    emit(a, d)

def c_search(a):
    q = a.query.strip().lower(); toks = re.findall(r'[\w.&-]+', q); best = {}
    for d in doms(a):
        for o in kb(d).by.values():
            K = KIND[o['type']]
            if (a.type and K != a.type) or (K == 'analytic' and a.type != 'analytic') or (dead(o) and not a.all): continue
            name, al, desc = o.get('name', '').lower(), [x.lower() for x in aliases(o)], (o.get('description') or '').lower()
            if not all(t in name or t in desc or any(t in x for x in al) or t == eid(o).lower() for t in toks): continue
            sc = 200 * (q == eid(o).lower()) + (120 if q == name else 60 if q in name else 0) + (100 if q in al else 50 if any(q in x for x in al) else 0)
            sc += sum(12 for t in toks if t in name) + sum(8 for t in toks if any(t in x for x in al)) + min(desc.count(q), 5) * 3 + 5
            hit = next((x for x in aliases(o) if q in x.lower()), '') if q not in name else ''
            key = (eid(o), o['type'])
            if key in best: best[key]['domain'] += ',' + d
            else: best[key] = dict(score=round(sc * (0.3 if dead(o) else 1)), id=eid(o), name=o['name'], type=K, status=state(o), domain=d, matched_alias=hit)
    res = sorted(best.values(), key=lambda r: (-r['score'], r['id']))
    emit(a, {'title': f'Search: {a.query}', 'total_matches': len(res), 'results': res[:a.limit or None]})

def read_text(p):
    if p == '-': return sys.stdin.read()
    if not os.path.isfile(p): die(f'file not found: {p}')
    with open(p, encoding='utf-8', errors='replace') as f: return f.read()

def tactic_tags(text): return {t.replace('_', '-') for t in re.findall(r'attack\.([a-z]+(?:[_-][a-z]+)*)', text)}

def c_validate(a):
    text = read_text(a.file); seen = defaultdict(list); K = [kb(d) for d in doms(a)]
    for n, line in enumerate(text.splitlines(), 1):
        for m in ID_RE.finditer(line):
            raw = m.group(2)
            if raw[0].islower() and raw[0] != 't' and not m.group(1): continue
            seen[raw.upper()].append(n)
    rows, repl, cnt, ent = [], {}, Counter(), False
    for i in sorted(seen):
        hit = next(((k, k.one(i)) for k in K if k.one(i) and not dead(k.one(i))), None) or next(((k, k.one(i)) for k in K if k.one(i)), None)
        r = dict(id=i, lines=','.join(map(str, seen[i][:6])) + ('...' if len(seen[i]) > 6 else ''), status='ok', name='', domain='', action='')
        if not hit:
            if i[0] == 'A' and not i.startswith('AN'): continue
            r['status'] = 'UNKNOWN'; r['action'] = 'not in ATT&CK ' + '/'.join(k.dom for k in K) + f' v{K[0].ver}; fix or remove'
            par = next((k.one(i.split('.')[0]) for k in K if '.' in i and k.one(i.split('.')[0])), None)
            if par: r['action'] = f"no such sub-technique; parent {eid(par)} {par['name']} is {state(par)}" + (f" -> {eid(k.chain(par)[-1])}" if par.get('revoked') and k.chain(par) else '')
        else:
            k, o = hit; r.update(name=o['name'], domain=k.dom); ent |= k.dom == 'enterprise' and i[0] == 'T'
            if o.get('revoked'):
                ch = k.chain(o); r['status'] = 'REVOKED'
                r['action'] = (f"replace with {eid(ch[-1])} {ch[-1]['name']} [{', '.join(k.tacs(ch[-1]))}]" if ch else 'no replacement in data; re-map from evidence')
                if ch: repl[i] = eid(ch[-1])
            elif o.get('x_mitre_deprecated'): r['status'] = 'DEPRECATED'; r['action'] = 're-map from evidence (no direct replacement)'
            elif KIND[o['type']] == 'technique' and '.' not in i:
                subs = [eid(x) for x in k.rel(o, 'subtechnique-of', rev=True)]
                both = [x for x in subs if x in seen]
                if both: r['status'] = 'info'; r['action'] = 'parent listed together with sub(s) ' + ','.join(both) + ' - keep parent only if evidence is generic'
                elif subs: r['status'] = 'info'; r['action'] = f'parent with {len(subs)} sub-techniques - use the most specific sub the evidence supports'
        cnt[r['status']] += 1; rows.append(r)
    notes = []
    legacy = [n for n, l in enumerate(text.splitlines(), 1) if re.search(r'defen[sc]e[\s_-]*evasion', l, re.I)]
    if legacy and (ent or a.domain == 'enterprise'):
        cnt['LEGACY'] += 1; notes.append(f"Legacy 'Defense Evasion' on line(s) {','.join(map(str, legacy[:8]))}: since v19 Enterprise TA0005 is Stealth and breaking defenses is TA0112 Defense Impairment. Re-check each technique's tactic (Mobile TA0030 still uses Defense Evasion).")
    tags = tactic_tags(text) & (set().union(*[set(k.short) for k in K]) | {'defense-evasion'})
    if tags and len(re.findall(r'^detection:', text, re.M)) == 1:  # single Sigma rule; use `sigma <dir>` for rule sets
        for r in rows:
            o = next((k.one(r['id']) for k in K if k.dom == r['domain']), None)
            if r['status'] in ('ok', 'info') and o and o['type'] == 'attack-pattern':
                tt = next(k for k in K if k.dom == r['domain']).tacs(o)
                if not set(tt) & tags: cnt['MISMATCH'] += 1; notes.append(f"Tactic mismatch: {r['id']} {r['name']} belongs to [{', '.join(tt)}] but the file's tactic tags are [{', '.join(sorted(tags))}].")
    if a.fix and repl:
        fixed = ID_RE.sub(lambda m: (m.group(1) or '') + (repl[m.group(2).upper()].lower() if m.group(2).islower() else repl[m.group(2).upper()]) if m.group(2).upper() in repl else m.group(0), text)
        with open(a.fix, 'w', encoding='utf-8') as f: f.write(fixed)
        notes.append(f'Wrote {a.fix} with {len(repl)} revoked ID(s) replaced. Tactic names/tags and technique names were NOT changed - review them.')
    bad = sum(cnt[x] for x in ('UNKNOWN', 'REVOKED', 'DEPRECATED', 'LEGACY', 'MISMATCH'))
    emit(a, {'title': f'ATT&CK ID validation: {a.file}', 'attack_version': K[0].ver, 'ids_found': len(rows), 'summary': dict(cnt), 'result': 'FAIL - fix before publishing' if bad else 'PASS',
             'findings': [r for r in rows if r['status'] != 'ok' or a.all], 'notes': notes})
    return 1 if bad else 0

def make_layer(k, name, items, desc='', maxv=None, colors=None, legend=None):
    """items: {technique_id: (score|None, comment)} -> Navigator layer dict (one entry per tactic the technique is in)."""
    techs, shown = [], {i.split('.')[0] for i in items if '.' in i}
    for i in sorted(set(items) | shown):
        o = k.one(i); sc, cm = items.get(i, (None, ''))
        for tac in k.tacs(o):
            e = {'techniqueID': i, 'tactic': tac, 'enabled': True}
            if sc is not None: e['score'] = sc
            if cm: e['comment'] = cm
            if i in shown: e['showSubtechniques'] = True
            techs.append(e)
    scores = [v[0] for v in items.values() if v[0] is not None]
    return {'name': name, 'versions': {'attack': k.ver.split('.')[0], **NAV}, 'domain': k.dom + '-attack', 'description': desc, 'sorting': 3, 'hideDisabled': False,
            'techniques': techs, 'gradient': {'colors': colors or ['#ffffff', '#ff6666'], 'minValue': 0, 'maxValue': maxv or max(scores + [1])},
            'legendItems': legend or [], 'metadata': [{'name': 'ATT&CK data version', 'value': k.ver}, {'name': 'generated', 'value': time.strftime('%Y-%m-%d')}],
            'selectSubtechniquesWithParent': False}

def resolve_tech(k, i, where=''):
    """-> active technique ID (following revocations) or None, with warnings."""
    o = k.one(i)
    if not o or o['type'] != 'attack-pattern': warn(f'{where}{i}: unknown technique in {k.dom}-attack v{k.ver} - skipped'); return None
    if o.get('revoked'):
        ch = k.chain(o)
        if not ch or dead(ch[-1]): warn(f'{where}{i}: revoked without active replacement - skipped'); return None
        warn(f'{where}{i} is revoked -> using {eid(ch[-1])} {ch[-1]["name"]}'); return eid(ch[-1])
    if o.get('x_mitre_deprecated'): warn(f'{where}{i}: deprecated - skipped'); return None
    return eid(o)

def write_layer(a, layer, path):
    s = json.dumps(layer, indent=2)
    if path and path != '-':
        with open(path, 'w', encoding='utf-8') as f: f.write(s)
        print(f"layer written: {path} ({len(layer['techniques'])} entries, {layer['domain']} v{layer['versions']['attack']}, layer format {NAV['layer']})", file=sys.stderr)
    else: print(s)

def c_layer(a):
    if bool(a.techniques) == bool(a.source): die('give either --techniques FILE or --from ID [ID ...]')
    if a.techniques:
        rows = [r for r in csv.reader(io.StringIO(read_text(a.techniques))) if r and any(c.strip() for c in r)]
        k = pick_domain(a, [m.group(0) for r in rows for m in TID_RE.finditer(' '.join(r))]); items = {}
        for r in rows:
            j = next((n for n, c in enumerate(r) if TID_RE.fullmatch(c.strip())), None)
            ids = [r[j].strip()] if j is not None else TID_RE.findall(' '.join(r)); rest = [c.strip() for c in r[j + 1:]] if j is not None else []
            sc = None; cm = ''
            if rest and re.fullmatch(r'-?\d+(\.\d+)?', rest[0]): sc = float(rest[0]) if '.' in rest[0] else int(rest[0]); rest = rest[1:]
            elif rest and rest[0].lower() in STATUS: sc = STATUS[rest[0].lower()]; rest = rest[1:]
            cm = '; '.join(c for c in rest if c)
            for i in ids:
                t = resolve_tech(k, i.upper())
                if t: items[t] = (sc if sc is not None else 1, '; '.join(x for x in (items.get(t, (0, ''))[1], cm) if x))
        name, desc = a.name or f'Techniques from {a.techniques}', f'{len(items)} techniques'
    else:
        k, first, _ = lookup(a, a.source[0], ('group', 'software', 'campaign')); ents = [first[0]] + [(k.find(q, ('group', 'software', 'campaign')) or die(f'{q!r} not found in {k.dom}-attack'))[0] for q in a.source[1:]]
        sets = [k.used(e, a.with_software) for e in ents]; label = [f"{eid(e)} {e['name']}" for e in ents]
        ids = set(sets[0]) if a.op != 'union' else set().union(*sets)
        for s2 in sets[1:]: ids = ids & set(s2) if a.op == 'intersection' else ids - set(s2) if a.op == 'diff' else ids
        items = {i: (sum(1 for s2 in sets if i in s2), 'Used by: ' + ', '.join(l for l, s2 in zip(label, sets) if i in s2)) for i in ids}
        opn = {'union': ' + ', 'intersection': ' AND ', 'diff': ' minus '}[a.op]
        name = a.name or opn.join(eid(e) for e in ents); desc = f"{a.op} of {', '.join(label)}; score = number of listed entities using the technique" + ('; includes techniques of their software' if a.with_software else '')
    if not items: warn('no techniques in result' + ('' if a.techniques or a.with_software else ' - groups in mobile/ics often map only via software: try --with-software'))
    write_layer(a, make_layer(k, name, items, desc), a.output)

def coverage(k, det, groups=None):
    """det: {technique_id: [(status_int, detection_name), ...]} -> (tactic rows, gap rows, layer items)."""
    best = {i: max(s for s, _ in v) for i, v in det.items()}; gm = k.groupmap(); gset = set(groups) if groups else None
    def sc(t):
        subs = [best.get(eid(x), 0) for x in k.rel(t, 'subtechnique-of', rev=True)]
        return max([best.get(eid(t), 0)] + subs)
    techs = sorted(k.all('technique'), key=eid); rows = []
    for short, tac in k.short.items():
        ts = [sc(t) for t in techs if short in k.tacs(t)]; n = len(ts) or 1
        rows.append({'tactic': tac['name'], 'id': eid(tac), 'techniques': len(ts), 'logs+': sum(1 for x in ts if x >= 1), 'rule+': sum(1 for x in ts if x >= 2),
                     'tested': sum(1 for x in ts if x >= 3), 'coverage_%': round(100 * sum(1 for x in ts if x >= 2) / n, 1), 'tested_%': round(100 * sum(1 for x in ts if x >= 3) / n, 1)})
    gaps, items = [], {}
    for t in techs:
        i = eid(t); s = sc(t); g = sorted(gm.get(i, set()) & gset if gset else gm.get(i, set()))
        names = '; '.join(dict.fromkeys(n for _, n in sorted(det.get(i, []), reverse=True) if n))
        items[i] = (s, (names or ('inherited from sub-technique' if s else 'no detection')) + (f' | groups: {len(g)}' if g else ''))
        if s < 2 and (g or not gset):
            gaps.append(dict(id=i, name=k.tname(t), tactics=', '.join(k.tacs(t)), status=[x for x, v in STATUS.items() if v == s][0], groups=len(g),
                             examples=', '.join(g[:5]), campaigns=len(k.rel(t, 'uses', rev=True, kinds=('campaign',))), DET=', '.join(eid(x) for x in k.rel(t, 'detects', rev=True))))
    gaps.sort(key=lambda r: (-r['groups'], -r['campaigns'], r['id']))
    return rows, gaps, items

def cov_report(a, k, det, title, extra=None):
    groups = None
    if a.groups:
        groups = [eid((k.find(g, ('group',)) or die(f'group {g!r} not found in {k.dom}-attack'))[0]) for g in a.groups.split(',') if g.strip()]
    rows, gaps, items = coverage(k, det, groups); tot = sum(1 for v in items.values() if v[0] >= 2)
    d = {'title': title, 'attack_version': k.ver, 'domain': k.dom + '-attack', 'techniques_with_rule_or_better': f'{tot} of {len(items)} ({round(100 * tot / len(items), 1)}%)',
         'scoring': 'none=0 logs=1 rule=2 tested=3; coverage_% = rule or tested; a parent inherits its best sub-technique score, subs never inherit from the parent',
         'gap_ranking': 'by number of groups using the technique' + (f" (restricted to {', '.join(groups)})" if groups else ''), **(extra or {}),
         'coverage_by_tactic': rows, 'top_gaps': gaps[:a.top], 'total_gaps': len(gaps)}
    if a.layer:
        write_layer(a, make_layer(k, a.name or title, items, 'Detection coverage: 0 none, 1 logs only, 2 rule, 3 tested', 3, COLORS,
                                  [{'label': f'{v} {n}', 'color': COLORS[v]} for n, v in STATUS.items()]), a.layer)
    lim, a.limit = a.limit, 0
    emit(a, d); a.limit = lim

def c_coverage(a):
    rows = [r for r in csv.reader(io.StringIO(read_text(a.file))) if r and r[0].strip() and not r[0].lstrip().startswith('#')]
    k = pick_domain(a, [r[0].strip() for r in rows]); det = defaultdict(list); bad = []
    for n, r in enumerate(rows, 1):
        i = r[0].strip().upper(); st = (r[2].strip().lower() if len(r) > 2 else 'rule')
        if not TID_RE.fullmatch(i):
            if n > 1: bad.append(f'row {n}: {r[0]!r} is not a technique ID')
            continue
        if st not in STATUS: bad.append(f'row {n}: status {st!r} not in none|logs|rule|tested - treated as none'); st = 'none'
        t = resolve_tech(k, i, f'row {n}: ')
        if not t: bad.append(f'row {n}: {i} unknown/deprecated - ignored'); continue
        if t != i: bad.append(f'row {n}: {i} revoked -> counted as {t}')
        det[t].append((STATUS[st], r[1].strip() if len(r) > 1 else ''))
    cov_report(a, k, det, f'Detection coverage: {a.file}', {'input_issues': bad})

def c_sigma(a):
    if not os.path.isdir(a.dir): die(f'not a directory: {a.dir}')
    files = sorted(os.path.join(r, f) for r, _, fs in os.walk(a.dir) for f in fs if f.lower().endswith(('.yml', '.yaml')))
    rules = []
    for p in files:
        t = read_text(p); m = re.search(r'^title:\s*(.+)$', t, re.M)
        if not re.search(r'^detection:', t, re.M): continue
        rules.append(dict(file=os.path.relpath(p, a.dir), title=(m.group(1).strip().strip('"\'') if m else os.path.basename(p)),
                          ids=sorted({x.upper() for x in re.findall(r'attack\.(t\d{4}(?:\.\d{3})?)\b', t, re.I)}), tags=tactic_tags(t.lower())))
    k = pick_domain(a, [i for r in rules for i in r['ids']]); det = defaultdict(list); issues = []; out = []
    for r in rules:
        tacs = r['tags'] & (set(k.short) | {'defense-evasion'})
        if 'defense-evasion' in tacs and k.dom == 'enterprise': issues.append(dict(file=r['file'], issue='legacy tag attack.defense-evasion', fix='use attack.stealth or attack.defense-impairment (per technique)'))
        for i in r['ids']:
            o = k.one(i)
            if not o: issues.append(dict(file=r['file'], issue=f'{i} unknown', fix='fix or remove tag')); continue
            if dead(o):
                ch = k.chain(o); issues.append(dict(file=r['file'], issue=f'{i} {state(o).lower()}', fix=f"retag attack.{eid(ch[-1]).lower()} ({ch[-1]['name']}; {', '.join(k.tacs(ch[-1]))})" if ch else 're-map'))
                if not ch or dead(ch[-1]): continue
                o = ch[-1]
            elif tacs and not set(k.tacs(o)) & tacs: issues.append(dict(file=r['file'], issue=f"{i} tactic mismatch: tagged {', '.join(sorted(tacs))}", fix='technique is in: ' + ', '.join(k.tacs(o))))
            det[eid(o)].append((STATUS[a.status], r['title'])); out.append([eid(o), r['title'], a.status])
    if a.csv:
        with open(a.csv, 'w', newline='', encoding='utf-8') as f: csv.writer(f).writerows([['technique_id', 'detection_name', 'status']] + sorted(out))
    cov_report(a, k, det, f'Sigma coverage: {a.dir}', {'rules_scanned': len(rules), 'rules_with_technique_tags': sum(1 for r in rules if r['ids']),
               'rules_without_technique_tags': [r['file'] for r in rules if not r['ids']][:50], 'distinct_techniques': len(det), 'tag_issues': issues})

def bundle(spec):
    m = re.fullmatch(r'(enterprise|mobile|ics)[@-](\d+(?:\.\d+)?)', spec)
    if os.path.isfile(spec): return KB(os.path.basename(spec), spec)
    if not m: die(f'{spec}: not a file and not <domain>@<version> (e.g. enterprise@19.1)')
    ver = m.group(2) if '.' in m.group(2) else m.group(2) + '.0'; p = os.path.join(DATA, f'{m.group(1)}-{ver}.json')
    if not os.path.exists(p):
        b = fetch(STIX.format(d=m.group(1), v='-' + ver))
        if b is None: die(f'{spec}: no such release (versions are listed in index.json of mitre-attack/attack-stix-data)')
        os.makedirs(DATA, exist_ok=True)
        with open(p, 'wb') as f: f.write(b)
    return KB(m.group(1), p)

def c_diff(a):
    old, new = bundle(a.old), bundle(a.new); cats = defaultdict(list); want = None if a.type == 'all' else a.type
    for sid, n in new.by.items():
        o = old.by.get(sid); K = KIND[n['type']]; r = dict(id=eid(n), name=n['name'], type=K, detail='')
        if o is None:
            if not dead(n): r['detail'] = ', '.join(new.tacs(n)); cats['added'].append(r)
        elif n.get('revoked') and not o.get('revoked'):
            ch = new.chain(n); r['detail'] = 'replaced by ' + (f"{eid(ch[-1])} {ch[-1]['name']}" if ch else '?'); cats['revoked'].append(r)
        elif n.get('x_mitre_deprecated') and not o.get('x_mitre_deprecated'): cats['deprecated'].append(r)
        elif dead(n): continue
        else:
            ch = []
            if o['name'] != n['name']: ch.append(f"renamed from '{o['name']}'")
            if old.tacs(o) != new.tacs(n) and K == 'technique': ch.append(f"tactics {','.join(old.tacs(o)) or '-'} -> {','.join(new.tacs(n)) or '-'}")
            if sorted(o.get('x_mitre_platforms', [])) != sorted(n.get('x_mitre_platforms', [])): ch.append('platforms changed')
            if o.get('x_mitre_version') != n.get('x_mitre_version'): ch.append(f"v{o.get('x_mitre_version')} -> v{n.get('x_mitre_version')}")
            if ch: r['detail'] = '; '.join(ch); cats['changed'].append(r)
            elif o.get('modified') != n.get('modified'): cats['minor_edit'].append(r)
    cats['removed'] = [dict(id=eid(o), name=o['name'], type=KIND[o['type']], detail=state(o)) for sid, o in old.by.items() if sid not in new.by]
    order = ('added', 'revoked', 'deprecated', 'changed', 'removed', 'minor_edit'); kinds = sorted({r['type'] for c in cats.values() for r in c})
    d = {'title': f'ATT&CK diff: {old.dom} v{old.ver} -> v{new.ver}', 'old': f'{old.path} (v{old.ver})', 'new': f'{new.path} (v{new.ver})',
         'summary': [dict(type=K, **{c: sum(1 for r in cats[c] if r['type'] == K) for c in order}) for K in kinds], 'showing_type': a.type}
    for c in order[:5]: d[c] = sorted([r for r in cats[c] if not want or r['type'] == want], key=lambda r: (r['type'], r['id']))
    emit(a, d)

def atomic_tests(tid):
    tests, cur, sec = [], None, None
    for ln in cached(f'{ART}{tid}/{tid}.yaml').splitlines():
        m = re.match(r'  (\w+):\s*(.*)', ln)
        if ln.startswith('- name:'): cur = dict(technique=tid, test=len(tests) + 1, name=ln[7:].strip().strip('"\''), platforms=[], executor='', elevation='', guid=''); tests.append(cur); sec = None
        elif cur is None: continue
        elif m:
            sec = m.group(1)
            if sec == 'auto_generated_guid': cur['guid'] = m.group(2)
        elif sec == 'supported_platforms' and ln.startswith('  - '): cur['platforms'].append(ln[4:].strip())
        elif sec == 'executor' and re.match(r'    (name|elevation_required):', ln):
            f, v = ln.strip().split(':', 1); cur['executor' if f == 'name' else 'elevation'] = v.strip()
    return tests

def c_atomic(a):
    k, objs, _ = lookup(a, a.query, ('technique',)); o = objs[0]; note = []
    if dead(o):
        ch = k.chain(o); note.append(f"{eid(o)} is {state(o)}" + (f"; current ID is {eid(ch[-1])} {ch[-1]['name']} (both checked)" if ch else ''))
        ids = [eid(o)] + [eid(x) for x in ch]
    else:
        ids = [eid(o)] + ([] if a.no_subs else [eid(x) for x in k.rel(o, 'subtechnique-of', rev=True)])
        ids += [eid(x) for x in k.rel(o, 'revoked-by', rev=True, alive=False) if a.legacy]
    tests = [t for i in dict.fromkeys(ids) for t in atomic_tests(i)]
    if not tests: note.append('No Atomic Red Team tests found for these IDs.' + (' Atomic can lag ATT&CK renumbering - retry with --legacy to include superseded IDs.' if k.dom == 'enterprise' else ' Atomic Red Team covers Enterprise techniques only.'))
    o = ([x for x in k.chain(o) if not dead(x)] or [o])[-1]
    emit(a, {'title': f"Atomic Red Team tests: {eid(o)} {o['name']}", 'attack_version': k.ver, 'tactics': k.tacs(o), 'ids_checked': list(dict.fromkeys(ids)), 'tests_found': len(tests),
             'note': ' '.join(note), 'tests': tests, 'source': 'github.com/redcanaryco/atomic-red-team (atomics/<ID>/<ID>.yaml). Names/GUIDs only; run tests only in authorized lab scope, e.g. Invoke-AtomicTest <ID> -TestGuids <guid>.'})

def main():
    com = argparse.ArgumentParser(add_help=False)
    com.add_argument('-d', '--domain', choices=DOMAINS + ('auto', 'all'), default='auto', help='default auto: enterprise, then mobile, then ics')
    com.add_argument('--json', action='store_true', help='JSON output instead of markdown')
    com.add_argument('--limit', type=int, default=40, help='max rows per markdown table (0 = all)')
    com.add_argument('--full', action='store_true', help='do not truncate descriptions')
    ap = argparse.ArgumentParser(description=__doc__); sub = ap.add_subparsers(dest='cmd', required=True)
    def cmd(name, fn, hlp, *args):
        p = sub.add_parser(name, parents=[com], help=hlp); p.set_defaults(fn=fn)
        for flags, kw in args: p.add_argument(*flags, **kw)
    Q = (('query',), dict(help='ID, name or alias'))
    cov = [(('--groups',), dict(help='comma list of groups (ID/name/alias) to rank gaps by')), (('--top',), dict(type=int, default=25, help='gap rows to show')),
           (('--layer',), dict(metavar='OUT.json', help='also write a Navigator layer')), (('--name',), dict(help='layer name'))]
    cmd('update', c_update, 'download/refresh STIX bundles', (('--force',), dict(action='store_true')), (('--release',), dict(metavar='X.Y', help='fetch a specific release, e.g. 19.1 -> <domain>-19.1.json')))
    cmd('version', c_version, 'show data versions'); cmd('stats', c_stats, 'object counts')
    cmd('get', c_get, 'full detail for any ID or name', Q); cmd('group', lambda a: c_get(a, ('group',)), 'group profile', Q)
    cmd('software', lambda a: c_get(a, ('software',)), 'software profile', Q); cmd('campaign', lambda a: c_get(a, ('campaign',)), 'campaign profile', Q)
    cmd('search', c_search, 'ranked keyword search', Q, (('--type',), dict(choices=sorted(set(KIND.values())))), (('--all',), dict(action='store_true', help='include revoked/deprecated')))
    cmd('validate', c_validate, 'check every ATT&CK ID in a file (or - for stdin)', (('file',), {}), (('--all',), dict(action='store_true', help='list valid IDs too')), (('--fix',), dict(metavar='OUT', help='write a copy with revoked IDs replaced')))
    cmd('layer', c_layer, 'build a Navigator layer', (('--techniques',), dict(metavar='CSV', help='technique_id[,score][,comment] rows or free text (- = stdin)')),
        (('--from',), dict(dest='source', nargs='+', metavar='ID', help='group/software/campaign IDs or names')), (('--op',), dict(choices=('union', 'intersection', 'diff'), default='union')),
        (('--with-software',), dict(action='store_true', help="add techniques of the entities' software")), (('--name',), {}), (('-o', '--output'), dict(help='output file (default stdout)')))
    cmd('coverage', c_coverage, 'coverage + ranked gaps from detections.csv (technique_id,detection_name,status)', (('file',), {}), *cov)
    cmd('sigma', c_sigma, 'coverage from Sigma rule tags', (('dir',), {}), (('--status',), dict(choices=tuple(STATUS), default='rule', help='status to assign to rules')), (('--csv',), dict(metavar='OUT.csv', help='export detections.csv')), *cov)
    cmd('diff', c_diff, 'compare two bundles (file paths or <domain>@<version>)', (('old',), {}), (('new',), {}), (('--type',), dict(default='technique', choices=sorted(set(KIND.values())) + ['all'])))
    cmd('atomic', c_atomic, 'Atomic Red Team tests for a technique (names only)', Q, (('--no-subs',), dict(action='store_true')), (('--legacy',), dict(action='store_true', help='also check IDs this technique superseded')))
    a = ap.parse_args(); sys.exit(a.fn(a) or 0)

if __name__ == '__main__':
    try: main()
    except BrokenPipeError: pass
PYEOF
python3 -I ~/attack_tools/attack.py update && python3 -I ~/attack_tools/attack.py version
```

Always run it as `python3 -I ~/attack_tools/attack.py` (below: `attack`). Data lives in `~/attack-data` (override with `ATTACK_DATA`); keep downloaded data and scripts in separate folders. Bundles come from `raw.githubusercontent.com/mitre-attack/attack-stix-data` (`<domain>-attack/<domain>-attack.json`, pinned releases `<domain>-attack-<X.Y>.json`, version list in `index.json`). If GitHub is unreachable, use WebFetch on `https://attack.mitre.org/techniques/<ID>/` and say the data came from the website. Alternative library for custom scripts: `pip install mitreattack-python --break-system-packages` (`MitreAttackData`, e.g. `get_techniques_used_by_group`).

### Commands

Global options (after the command): `-d enterprise|mobile|ics` (default auto: enterprise, then mobile, then ics), `--json`, `--limit N` (table rows, 0 = all), `--full` (untruncated descriptions). Default output is markdown tables. Exit code: 0 ok, 1 validation failed, 2 error.

| Command | What it does |
|---|---|
| `attack update [--force] [--release 19.1]` | Refresh bundles (skips if < 24h old); `--release` saves `<domain>-<X.Y>.json` |
| `attack version` / `attack stats` | Data version per domain / live object counts |
| `attack get <ID or name>` | Full detail for any object (T, TA, G, S, C, M, DET, AN, DC, A): tactics, platforms, parent/subs, mitigations, DET -> AN -> DC with log sources, groups/software/campaigns using it, revoked/deprecated status with replacement chain and what it supersedes |
| `attack search "<text>" [--type group] [--all]` | Ranked search over names, aliases, descriptions (finds "Cozy Bear" -> G0016 APT29) |
| `attack group\|software\|campaign <ID, name or alias>` | Profile: techniques with tactic and source (direct or via campaign), software, campaigns, attribution |
| `attack validate <file or -> [--fix out] [--all]` | Extracts every ID from text/CSV/JSON/Sigma YAML. Flags unknown, revoked (with replacement and its tactic), deprecated, legacy Defense Evasion, tactic-tag mismatch (single Sigma rule), bad sub-technique, parent-vs-sub overlap. `--fix` writes a copy with revoked IDs replaced |
| `attack layer --techniques <csv or ->` | Navigator layer from `technique_id[,score][,comment]` rows (or free text). Revoked IDs are auto-replaced with a warning |
| `attack layer --from <ID...> [--op union\|intersection\|diff] [--with-software]` | Layer for a group/software/campaign, or overlap of several (score = how many use the technique) |
| `attack coverage <detections.csv> [--groups G0016,FIN7] [--top 25] [--layer out.json]` | Rows `technique_id,detection_name,status` with status `none\|logs\|rule\|tested`. Per-tactic coverage %, gaps ranked by number of groups using each technique, optional layer |
| `attack sigma <dir> [--csv out.csv] [--layer out.json] [--groups ...]` | Reads `attack.tXXXX` tags from Sigma rules, reports tag issues, then the same coverage report |
| `attack diff <old> <new> [--type all]` | Added/revoked/deprecated/changed objects between bundles; args are files or `enterprise@19.1` (auto-download) |
| `attack atomic <technique> [--no-subs] [--legacy]` | Atomic Red Team test names, platforms, executor, GUID for a technique and its subs (no commands) |

Examples:

```bash
A="python3 -I $HOME/attack_tools/attack.py"
$A get T1562                      # revoked -> shows replacement T1685
$A get T0886 --json               # ICS technique, JSON
$A group "Cozy Bear" --limit 0    # full APT29 profile
$A validate draft_report.md       # run on every deliverable before sending
$A layer --from G0016 G0032 --op intersection -o overlap.json
$A coverage detections.csv --groups "APT29,Lazarus Group" --layer coverage.json
$A diff enterprise@19.1 enterprise@20.1
```

Layers use Navigator layer format **4.5** (Navigator 5.3.2, checked 2026-11-14 in `mitre-attack/attack-navigator`: `layers/spec/v4.5/layerformat.md`, `nav-app/package.json`). The tool writes one entry per tactic the technique belongs to, the right domain, and the ATT&CK major version from the data. Coverage scoring: none 0, logs 1, rule 2, tested 3; a parent inherits its best sub-technique score, a sub never inherits from its parent.

## 1. ID formats

| Prefix | Object | STIX type |
|---|---|---|
| TA#### | Tactic | x-mitre-tactic |
| T#### / T####.### | Technique / sub-technique | attack-pattern |
| G#### | Group | intrusion-set |
| S#### | Software | malware / tool |
| C#### | Campaign | campaign |
| M#### | Mitigation | course-of-action |
| DET#### | Detection strategy | x-mitre-detection-strategy |
| AN#### | Analytic | x-mitre-analytic |
| DC#### | Data component | x-mitre-data-component |
| A#### | Asset (ICS) | x-mitre-asset |

Relationships: `uses`, `mitigates`, `detects` (DET -> technique), `subtechnique-of`, `attributed-to` (campaign -> group), `revoked-by`, `targets` (ICS technique -> asset). Analytics hang off a detection strategy via `x_mitre_analytic_refs`; data components via each analytic's `x_mitre_log_source_references`. Filter out `revoked` and `x_mitre_deprecated` unless doing history. ICS techniques are T08xx/T09xx; mobile and enterprise share the T1xxx range, and groups/software can exist in several domains.

## 2. Current structure (v20.1)

### Enterprise: 15 tactics (since v19)

| ID | Tactic | Shortname |
|---|---|---|
| TA0043 | Reconnaissance | reconnaissance |
| TA0042 | Resource Development | resource-development |
| TA0001 | Initial Access | initial-access |
| TA0002 | Execution | execution |
| TA0003 | Persistence | persistence |
| TA0004 | Privilege Escalation | privilege-escalation |
| TA0005 | **Stealth** (was Defense Evasion, same ID) | stealth |
| TA0112 | **Defense Impairment** (new in v19) | defense-impairment |
| TA0006 | Credential Access | credential-access |
| TA0007 | Discovery | discovery |
| TA0008 | Lateral Movement | lateral-movement |
| TA0009 | Collection | collection |
| TA0011 | Command and Control | command-and-control |
| TA0010 | Exfiltration | exfiltration |
| TA0040 | Impact | impact |

Platforms: Windows, macOS, Linux, ESXi, IaaS, Network Devices, PRE, Office Suite, SaaS, Identity Provider, Containers.

### Mobile: 12 tactics (Android, iOS)
Initial Access TA0027, Execution TA0041, Persistence TA0028, Privilege Escalation TA0029, **Defense Evasion TA0030** (the Stealth split was Enterprise only), Credential Access TA0031, Discovery TA0032, Lateral Movement TA0033, Collection TA0035, Command and Control TA0037, Exfiltration TA0036, Impact TA0034.

### ICS: 12 tactics
Initial Access TA0108, Execution TA0104, Persistence TA0110, Privilege Escalation TA0111, Evasion TA0103, Discovery TA0102, Lateral Movement TA0109, Collection TA0100, Command and Control TA0101, Inhibit Response Function TA0107, Impair Process Control TA0106, Impact TA0105. ICS also has 18 assets (A####).

### Live counts, v20.1 (active objects; recompute with `attack stats`)

| Domain | Techniques | Subs | Groups | Software | Campaigns | Mitigations | DET | AN | DC |
|---|---|---|---|---|---|---|---|---|---|
| Enterprise | 227 | 479 | 178 | 842 | 57 | 44 | 706 | 1773 | 106 |
| Mobile | 78 | 47 | 20 | 129 | 3 | 13 | 125 | 213 | 29 |
| ICS | 78 | 26 | 14 | 25 | 10 | 53 | 104 | 300 | 40 |

## 3. Recent changes you must know (all verified in data)

**v18 (Oct 2025): detection model rebuilt.** Data sources were replaced by **Detection Strategies (DET)** -> **Analytics (AN, platform-specific logic with tunables)** -> **Data Components (DC, with log source name and channel)**. One DET per technique.

**v19 (2026-04-28): Defense Evasion split (Enterprise only).**
- TA0005 renamed **Stealth** (hiding: masquerading, obfuscation, hide artifacts, indicator removal).
- New **TA0112 Defense Impairment** (breaking defenses), 57 techniques incl. subs. 60 existing techniques had their tactic list changed.
- 23 new techniques, 17 revoked. Replacement map (`revoked-by`):

| Revoked | Replacement |
|---|---|
| T1562 Impair Defenses, T1562.001, T1562.006 | T1685 Disable or Modify Tools |
| T1562.002 / .008 / .011 / .012 | T1685.001 Windows Event Log / T1685.002 Cloud Log / T1685.003 Modify or Spoof Tool UI / T1685.004 Linux Audit System Log |
| T1070.001 / T1070.002 (log clearing) | T1685.005 Clear Windows Event Logs / T1685.006 Clear Linux or Mac System Logs |
| T1562.004 / .007 / .013 | T1686 Disable or Modify System Firewall / T1686.001 Cloud Firewall / T1686.002 Network Device Firewall (T1686.003 Windows Host Firewall is new) |
| T1562.009 / T1562.010 / T1562.003 | T1688 Safe Mode Boot / T1689 Downgrade Attack / T1690 Prevent Command History Logging |
| T1656 Impersonation / T1672 Email Spoofing | T1684.001 Impersonation / T1684.002 Email Spoofing (under new T1684 Social Engineering, tactic Stealth) |

- Also new in v19: T1687 Exploitation for Defense Impairment, T1682 Query Public AI Services, T1683 Generate Content (.001 Written, .002 Audio-Visual), T1027.018 Invisible Unicode. T1211 renamed Exploitation for Stealth.
- Test for each behavior: **is the actor hiding (Stealth) or breaking a defense (Defense Impairment)?**

**v19.2 (2026-08-05):** first Agile release (groups/software/campaigns).

**v20 (2026-10-13): AI-related techniques.** T1699 Direct Prompt Injection and T1698 Indirect Prompt Injection (Execution), T1700 AI-Enabled Exfiltration (Exfiltration), T1608.007 Stage Capabilities: AI Result Poisoning (Resource Development), T1685.007 Disable or Modify Tools: Impair Autonomous Defenses (Defense Impairment), T1696 Anti-Automation Evasion with .001 Automate CAPTCHA Completion and .002 Avoid CAPTCHA (Stealth), T1697 Steal Application Specific Passwords (Credential Access). Also present: T1588.007 Obtain Capabilities: Artificial Intelligence. No technique revocations between v19.1 and v20.1. Use MITRE ATLAS alongside ATT&CK for attacks on AI systems themselves.

## 4. Workflows

### A. Map a report or incident
1. List each observed behavior as one sentence: actor did X, with Y, on platform Z. Keep the evidence quote and source location. Redact secrets and PII now.
2. For each behavior pick the tactic by the actor's **goal at that step** (table in section 5), then find the technique: `attack search "<verb + object>"`, read `attack get <ID>` description and compare.
3. Choose the most specific sub-technique the evidence supports. Assign confidence.
4. Write the table (template in section 9). Run `attack validate` on the draft; fix every finding.
5. Optional: `attack layer --techniques mapped.csv -o incident.json`.

### B. Detection coverage and gaps
1. Build `detections.csv` (`technique_id,detection_name,status`). From Sigma: `attack sigma rules/ --csv detections.csv`. From SIEM/EDR exports: map each rule to technique IDs, then `validate`.
2. `attack coverage detections.csv --groups <relevant groups> --layer coverage.json`.
3. For each top gap run `attack get <ID>`: read its DET -> AN -> DC rows and compare the log sources to what is actually collected. Missing log source means status stays `none`; collected but no rule means `logs`.
4. Report with the coverage template. Say plainly that coverage % measures mapped rules, not detection quality.

### C. Threat-informed emulation plan
1. `attack group <name>` (or campaign). Add `attack layer --from <ID> --with-software` for the picture including tooling.
2. Order techniques by tactic flow. For each, `attack atomic <ID>` and pick tests by platform; note test GUIDs only.
3. For each step list expected telemetry (DC and log source from `attack get`) and the detection that should fire.
4. Check the CTID Adversary Emulation Library for an existing plan for that actor. Use the emulation template.

### D. Navigator layers
Use `attack layer` (never hand-write tactic names). Open at `https://mitre-attack.github.io/attack-navigator/` -> Open Existing Layer. Group overlap: `--op intersection` for shared tradecraft, `--op diff` for what is unique to the first entity, `union` score = number of entities using each technique (heat map for prioritization).

### E. Migrate pre-v19 or older content
1. `attack validate old.md --fix migrated.md` replaces revoked IDs. It does not change tactic labels or technique names: fix those by hand from the findings.
2. Every Enterprise "Defense Evasion" label: look up the technique's current tactic (`attack get`), which is Stealth or Defense Impairment (or both removed).
3. `attack diff enterprise@<old> enterprise@<new>` lists added, revoked, renamed, and tactic-moved techniques for release notes. Official changelogs: `https://attack.mitre.org/docs/changelogs/`.
4. Record old and new ATT&CK versions in the deliverable.

## 5. Mapping methodology (CISA "Best Practices for MITRE ATT&CK Mapping" style)

Order of work: find the behavior -> research it -> identify the tactic (why) -> identify the technique (how) -> identify the sub-technique -> peer check. Map behaviors, not indicators: an IP address or hash is not a technique.

| Actor goal at this step | Tactic |
|---|---|
| Learn about the target before access | Reconnaissance |
| Build or buy infrastructure, accounts, tools | Resource Development |
| Get in | Initial Access |
| Run code | Execution |
| Keep access across restarts or credential changes | Persistence |
| Get higher permissions | Privilege Escalation |
| Avoid being noticed | Stealth |
| Disable, break, or blind a security control or log | Defense Impairment |
| Steal credentials or tokens | Credential Access |
| Learn the environment after access | Discovery |
| Move to other systems | Lateral Movement |
| Gather target data | Collection |
| Talk to compromised systems | Command and Control |
| Take data out | Exfiltration |
| Destroy, encrypt, disrupt, manipulate | Impact |

Confidence levels:
- **High**: direct evidence of the behavior (command line, log event, malware analysis) matches the technique description.
- **Medium**: behavior is clear but the sub-technique or tactic is inferred from context.
- **Low**: inferred from an outcome or a tool's known capability; state the assumption.

Common mistakes:
- Mapping a tool's full capability list instead of what was observed in this incident.
- One technique per sentence by reflex: one behavior can need two mappings (e.g., a scheduled task is Execution and Persistence only if evidence shows both goals), and many sentences need none.
- Picking the tactic from the technique's first listed tactic instead of the actor's goal.
- Parent used when a sub fits, or a sub guessed when evidence only supports the parent.
- Confusing look-alikes: Valid Accounts (using creds) vs Brute Force (getting them); Exploit Public-Facing Application (initial access) vs Exploitation for Privilege Escalation; Ingress Tool Transfer vs Lateral Tool Transfer; Phishing vs Phishing for Information.
- Using revoked IDs or pre-v19 tactic names. Mixing domains (ICS T08xx in an Enterprise layer).
- Treating mitigations or CVEs as techniques.

## 6. Detection engineering

- Start from `attack get <technique>`: each analytic row gives platform, data components, log source names (e.g., `WinEventLog:Sysmon`, `auditd:SYSCALL`, `AWS:CloudTrail`), and a logic summary. `attack get AN####` adds log channels (event codes) and tunable fields. `attack get DC####` lists every technique detectable from that data component: use it to justify onboarding a log source.
- Analytics are behavioral descriptions, not ready rules. Translate to your SIEM, tune the listed mutable fields, test with an Atomic test, then mark `tested`.
- Tag rules at the most specific level; one rule may carry several techniques.
- **Sigma tags**: lowercase `attack.<tactic-shortname>` and `attack.t1059.001`; also `attack.g0016`, `attack.s0002`. Checked 2026-11-14: sampled rules in SigmaHQ/sigma master already use `attack.defense-impairment` with `attack.t1685` / `attack.t1685.005`, and the Atomic Red Team index uses `stealth` and `defense-impairment`. The Sigma tags appendix (v2.1.0, 2025-08-02) still lists `defense-evasion`, so check the target repo's validators before bulk retagging. `attack sigma` reports legacy tags, revoked IDs, and tactic mismatches per rule.
- Rate robustness, not only presence: CTID Summiting the Pyramid (Sigma `stp.*` tags) scores how hard an analytic is to evade.
- Coverage numbers overstate reality. Report rule count, tested count, and log source availability separately.

## 7. Threat intelligence

- Profile: `attack group <alias>` gives techniques (direct and via attributed campaigns), software, and campaigns. Group pages lag current reporting; note the group object's modified date and add recent vendor reporting with citations.
- Aliases are vendor-specific and overlap imperfectly. Say "tracked by MITRE as G0016 (APT29)" and keep vendor names as reported.
- Overlap: `attack layer --from A B C --op intersection` for common tradecraft worth detecting first; `union` scores for sector heat maps. Shared techniques do not prove shared identity.
- Prioritize by: groups targeting the organization's sector and region, then techniques seen in recent campaigns (C####), then prevalence (`coverage` gap ranking).
- Software-heavy actors (and most Mobile/ICS groups) need `--with-software` to show real technique use.

## 8. Purple teaming and cross-framework links

| Resource | Use | Note |
|---|---|---|
| Atomic Red Team (redcanaryco/atomic-red-team) | Small per-technique tests; `attack atomic <ID>` | Enterprise only; already on v19+ IDs. Names and GUIDs only in outputs |
| MITRE Caldera (github.com/mitre/caldera) | Automated adversary emulation with ability-to-technique mapping | README now references apache/caldera; confirm current home |
| CTID Adversary Emulation Library (center-for-threat-informed-defense/adversary_emulation_library) | Full and micro emulation plans per actor | Check which ATT&CK version each plan used |
| D3FEND (d3fend.mitre.org) | Defensive countermeasures mapped to ATT&CK techniques | Use for "what control counters this" |
| MITRE Engage (engage.mitre.org) | Adversary engagement, deception, and denial activities | Pair with emulation and detection plans |
| ATLAS (atlas.mitre.org) | Attacks on AI/ML systems | Pair with T1698-T1700, T1608.007, T1685.007 |
| CAPEC / CWE | Attack patterns and weaknesses | Some techniques carry `capec` external references |
| CTID Mappings Explorer (ctid.mitre.org/mappings) | NIST 800-53, cloud platform controls, CVE and KEV to ATT&CK | Each mapping set is pinned to an ATT&CK version: check it, then `validate` the IDs |
| CISA KEV catalog | Exploited CVEs for prioritizing T1190 / T1203 / T1068-type gaps | Map CVE -> technique via Mappings Explorer, not by guess |
| Mitigations (M####) | `attack get <technique>` lists them; `attack get M####` lists techniques covered | Link to NIST 800-53 through Mappings Explorer |

Purple team loop: pick techniques from the gap list -> select Atomic tests -> run in authorized scope -> record which detection fired -> update `detections.csv` status to `tested` -> regenerate the layer.

## 9. Output templates

**Incident / report mapping** (header line: "ATT&CK Enterprise v20.1, mapped <date>, source <doc>")

| # | Time (UTC) | Evidence (redacted quote + source) | Tactic | Technique ID | Technique name | Confidence | Notes |
|---|---|---|---|---|---|---|---|

Follow with: unmapped behaviors and why, assumptions, validation result (`attack validate`: PASS).

**Coverage report**
1. Scope: ATT&CK version, domain, platforms, rule sources, date.
2. Summary: techniques with rule or better (n of N), tested (n), by tactic table (from `coverage`).
3. Top gaps table: Technique | Tactic | Groups using | Required data components | Log source present? | Recommended action | Owner.
4. Tag hygiene issues (revoked IDs, legacy tactics). 5. Navigator layer file. 6. Limits: coverage is not efficacy.

**Emulation plan**
1. Objective, authorized scope, rules of engagement, ATT&CK version, actor (G####/C####) with sources.
2. Step table: # | Tactic | Technique ID and name | Test reference (Atomic GUID or Caldera ability) | Platform | Expected telemetry (DC / log source) | Expected detection | Result.
3. Safety: test accounts and hosts only, cleanup steps, stop conditions. 4. Findings feed back into `detections.csv`.

## Sources
- Data: https://github.com/mitre-attack/attack-stix-data (index.json lists releases)
- Release notes: https://attack.mitre.org/resources/updates/ ; changelogs: https://attack.mitre.org/docs/changelogs/
- Navigator: https://github.com/mitre-attack/attack-navigator (layers/spec/v4.5/layerformat.md)
- Sigma tags: https://github.com/SigmaHQ/sigma-specification (specification/sigma-appendix-tags.md)
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team (atomics/Indexes/Indexes-CSV/index.csv)
- CISA mapping guide: https://www.cisa.gov/news-events/news/best-practices-mitre-attckr-mapping