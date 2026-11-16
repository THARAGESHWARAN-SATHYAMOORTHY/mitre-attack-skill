#!/usr/bin/env python3
"""attack.py - stdlib-only MITRE ATT&CK CLI (enterprise / mobile / ics). Run: python3 -I attack.py <command> -h"""
import argparse, csv, io, json, os, re, subprocess, sys, time, urllib.error, urllib.request
from collections import Counter, defaultdict

DATA = os.path.expanduser('~/attack-data')
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
