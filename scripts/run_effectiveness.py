#!/usr/bin/env python3
"""Reproducible rule-effectiveness harness.

Runs every Sigma rule in rules/sigma/ against the EVTX-ATTACK-SAMPLES JSONL corpus
(default: data/processed/evtx-json) and writes:
  tests/results/effectiveness.json           {rule_file: match_count}  (non-correlation rules)
  tests/results/effectiveness_evidence.json  corpus size + up to 3 evidence samples per rule
  tests/results/correlation_real.json        temporal / event_count correlation hits on the real corpus

Usage: python3 scripts/run_effectiveness.py [corpus_dir]
Field mapping: EventID/Channel/Computer -> Event.System; other fields -> Event.EventData, then Event.UserData.*
Logsource service/category is mapped to the event Channel (service -> its channel, category -> Sysmon); matching is case-insensitive like Sigma.
"""
import datetime, fnmatch, glob, ipaddress, json, os, re, sys
import yaml

class Unsupported(Exception): pass

# ---------- value matching (pySigma escaping rules) ----------
def sigma_pattern(v):
    out, i = [], 0
    while i < len(v):
        c = v[i]
        if c == "\\" and i + 1 < len(v) and v[i + 1] in "*?\\":
            out.append(re.escape(v[i + 1])); i += 2; continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c)); i += 1
    return "".join(out)

def norm(v):
    if isinstance(v, dict): v = v.get("#text")
    return v

def get_field(ev, name):
    e = ev.get("Event") or {}
    s = e.get("System") or {}
    if name == "EventID": return norm(s.get("EventID"))
    if name in ("Channel", "Computer"): return s.get(name)
    ed = e.get("EventData")
    if isinstance(ed, dict) and name in ed: return norm(ed[name])
    ud = e.get("UserData")
    if isinstance(ud, dict):
        for sub in ud.values():
            if isinstance(sub, dict) and name in sub: return norm(sub[name])
    return None

def text(v):
    return "" if v is None else str(v).lower() if isinstance(v, bool) else str(v)

def compile_item(key, val):
    parts = key.split("|"); field, mods = parts[0], parts[1:]
    kind, mode = "eq", "any"
    for m in mods:
        if m == "all": mode = "all"
        elif m in ("contains", "startswith", "endswith", "re", "exists", "lt", "lte", "gt", "gte", "cidr"): kind = m
        else: raise Unsupported("modifier |" + m)
    vals = val if isinstance(val, list) else [val]
    tests = []
    for v in vals:
        if kind == "exists":
            want = bool(v); tests.append(lambda x, want=want: (x is not None) == want)
        elif v is None:
            tests.append(lambda x: x is None or x == "")
        elif kind == "re":
            rx = re.compile(str(v)); tests.append(lambda x, rx=rx: x is not None and rx.search(text(x)) is not None)
        elif kind in ("lt", "lte", "gt", "gte"):
            n = float(v)
            def f(x, n=n, k=kind):
                try: x = float(x)
                except (TypeError, ValueError): return False
                return {"lt": x < n, "lte": x <= n, "gt": x > n, "gte": x >= n}[k]
            tests.append(f)
        elif kind == "cidr":
            net = ipaddress.ip_network(str(v), strict=False)
            def f(x, net=net):
                try: return ipaddress.ip_address(str(x)) in net
                except ValueError: return False
            tests.append(f)
        else:
            pat = sigma_pattern(str(v))
            pat = {"eq": pat, "contains": ".*" + pat + ".*", "startswith": pat + ".*", "endswith": ".*" + pat}[kind]
            rx = re.compile(pat, re.I | re.S)
            tests.append(lambda x, rx=rx: x is not None and rx.fullmatch(text(x)) is not None)
    agg = all if mode == "all" else any
    return lambda ev: agg(t(get_field(ev, field)) for t in tests)

def compile_selection(sel):
    if isinstance(sel, dict):
        items = []
        for k, v in sel.items():
            if "|" not in k and k == "": raise Unsupported("empty key")
            items.append(compile_item(k, v))
        return lambda ev: all(i(ev) for i in items)
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            subs = [compile_selection(x) for x in sel]; return lambda ev: any(s(ev) for s in subs)
        words = [str(x).lower() for x in sel]
        return lambda ev: any(w in json.dumps((ev.get("Event") or {}).get("EventData") or {}).lower() for w in words)
    w = str(sel).lower()
    return lambda ev: w in json.dumps((ev.get("Event") or {}).get("EventData") or {}).lower()

# ---------- condition parser ----------
def compile_condition(cond, names):
    if "|" in cond: raise Unsupported("aggregation in condition")
    toks = re.findall(r"\(|\)|[^\s()]+", cond); pos = [0]
    def peek(): return toks[pos[0]] if pos[0] < len(toks) else None
    def eat(): t = toks[pos[0]]; pos[0] += 1; return t
    def p_or():
        a = p_and()
        while peek() and peek().lower() == "or":
            eat(); b = p_and(); a = (lambda x, y: lambda r: x(r) or y(r))(a, b)
        return a
    def p_and():
        a = p_not()
        while peek() and peek().lower() == "and":
            eat(); b = p_not(); a = (lambda x, y: lambda r: x(r) and y(r))(a, b)
        return a
    def p_not():
        if peek() and peek().lower() == "not":
            eat(); a = p_not(); return lambda r: not a(r)
        return p_atom()
    def p_atom():
        t = eat()
        if t == "(":
            a = p_or(); eat(); return a
        nxt = peek()
        if nxt and nxt.lower() == "of" and (t.isdigit() or t.lower() in ("all", "any")):
            eat(); target = eat()
            sel = names if target.lower() == "them" else [n for n in names if fnmatch.fnmatchcase(n, target)]
            if not sel: raise Unsupported("no selection matches " + target)
            if t.lower() == "all": return lambda r, sel=sel: all(r[n] for n in sel)
            need = 1 if t.lower() == "any" else int(t)
            return lambda r, sel=sel, need=need: sum(1 for n in sel if r[n]) >= need
        if t not in names: raise Unsupported("unknown selection " + t)
        return lambda r, t=t: r[t]
    f = p_or()
    if pos[0] != len(toks): raise Unsupported("trailing tokens in condition")
    return f

SYSMON = "microsoft-windows-sysmon/operational"
SERVICE_CHANNEL = {
    "security": {"security"}, "system": {"system"}, "application": {"application"},
    "sysmon": {SYSMON}, "powershell": {"microsoft-windows-powershell/operational", "windows powershell"},
    "bits-client": {"microsoft-windows-bits-client/operational"}, "winrm": {"microsoft-windows-winrm/operational"},
    "wmi": {"microsoft-windows-wmi-activity/operational"},
    "taskscheduler": {"microsoft-windows-taskscheduler/operational"},
}

def allowed_channels(d):
    """Constrain by logsource: service -> Channel, any category -> Sysmon (rules use Sysmon EventIDs)."""
    ls = d.get("logsource") or {}
    if ls.get("service"): return SERVICE_CHANNEL.get(str(ls["service"]).lower())
    if ls.get("category"): return {SYSMON}
    return None

def compile_rule(d):
    det = d["detection"]; conds = det.get("condition")
    conds = conds if isinstance(conds, list) else [conds]
    sels = {k: compile_selection(v) for k, v in det.items() if k not in ("condition", "timeframe")}
    names = list(sels)
    fs = [compile_condition(str(c), names) for c in conds]
    return lambda ev: any(f({n: s(ev) for n, s in sels.items()}) for f in fs)

# ---------- time ----------
def parse_time(ev):
    s = ((((ev.get("Event") or {}).get("System") or {}).get("TimeCreated") or {}).get("#attributes") or {}).get("SystemTime")
    if not s: return None
    s = s.replace("Z", "+00:00")
    m = re.match(r"(.*\.\d{6})\d*(.*)", s)
    if m: s = m.group(1) + m.group(2)
    try: return datetime.datetime.fromisoformat(s).timestamp()
    except ValueError: return None

def span_seconds(s):
    m = re.fullmatch(r"(\d+)([smhd])", str(s).strip()); return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]

def main():
    corpus = sys.argv[1] if len(sys.argv) > 1 else "data/processed/evtx-json"
    if not os.path.isdir(corpus) or not os.path.isdir("rules/sigma"):
        sys.exit("[!] Run from project root; corpus dir not found: " + corpus)
    rules, corr, skipped = {}, {}, {}
    for f in sorted(glob.glob("rules/sigma/*.yml")):
        fn = os.path.basename(f); d = yaml.safe_load(open(f, encoding="utf-8"))
        if "correlation" in d: corr[fn] = d; continue
        try: rules[fn] = (d, compile_rule(d), allowed_channels(d))
        except Unsupported as e: skipped[fn] = str(e)
    group_fields = {}   # base rule name -> set(group-by fields needed)
    for fn, d in corr.items():
        for r in d["correlation"].get("rules", []):
            group_fields.setdefault(r, set()).update(d["correlation"].get("group-by", []))

    counts = {fn: 0 for fn in rules}; samples = {fn: [] for fn in rules}
    base_hits = {}      # rule name -> list of (time, groupdict, file)
    files = sorted(glob.glob(os.path.join(corpus, "**", "*.jsonl"), recursive=True))
    total = bad = 0
    for path in files:
        rel = os.path.relpath(path, corpus)
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line: continue
                try: ev = json.loads(line)
                except ValueError: bad += 1; continue
                total += 1
                chan = str(((ev.get("Event") or {}).get("System") or {}).get("Channel") or "").lower()
                for fn, (d, match, allowed) in rules.items():
                    if allowed and chan not in allowed: continue
                    if match(ev):
                        counts[fn] += 1
                        if len(samples[fn]) < 3:
                            s = (ev.get("Event") or {}).get("System") or {}
                            samples[fn].append({"file": rel, "EventRecordID": s.get("EventRecordID"), "Computer": s.get("Computer"), "time": ((s.get("TimeCreated") or {}).get("#attributes") or {}).get("SystemTime")})
                        nm = d.get("name")
                        if nm in group_fields:
                            base_hits.setdefault(nm, []).append((parse_time(ev), {g: str(get_field(ev, g)) for g in group_fields[nm]}, rel))

    os.makedirs("tests/results", exist_ok=True)
    json.dump(counts, open("tests/results/effectiveness.json", "w"), indent=1)
    json.dump({"corpus_dir": corpus, "files": len(files), "events": total, "unparseable_lines": bad,
               "unsupported_rules": skipped, "samples": samples}, open("tests/results/effectiveness_evidence.json", "w"), indent=1)

    creal = {}
    for fn, d in corr.items():
        c = d["correlation"]; typ = c.get("type"); span = span_seconds(c["timespan"]); gb = c.get("group-by", [])
        refs = c.get("rules", []); hits = []
        try:
            if typ == "temporal":
                groups = {}
                for r in refs:
                    for t, g, rel in base_hits.get(r, []):
                        if t is not None: groups.setdefault(tuple(g.get(x) for x in gb), []).append((t, r, rel))
                for key, evs in groups.items():
                    evs.sort(); i = 0
                    while i < len(evs):
                        j = i; names = set()
                        while j < len(evs) and evs[j][0] - evs[i][0] <= span: names.add(evs[j][1]); j += 1
                        if names >= set(refs): hits.append({"group": key, "start": evs[i][0], "files": sorted({e[2] for e in evs[i:j]})}); i = j
                        else: i += 1
            elif typ == "event_count":
                cond = c["condition"]; op, n = next(iter(cond.items())); n = int(n)
                if op not in ("gte", "gt"): raise Unsupported("event_count " + op)
                need = n if op == "gte" else n + 1; groups = {}
                for r in refs:
                    for t, g, rel in base_hits.get(r, []):
                        if t is not None: groups.setdefault(tuple(g.get(x) for x in gb), []).append((t, rel))
                for key, evs in groups.items():
                    evs.sort(); i = 0
                    while i < len(evs):
                        j = i
                        while j < len(evs) and evs[j][0] - evs[i][0] <= span: j += 1
                        if j - i >= need: hits.append({"group": key, "count": j - i, "files": sorted({e[1] for e in evs[i:j]})}); i = j
                        else: i += 1
            else: raise Unsupported("correlation type " + str(typ))
            creal[fn] = {"hits": len(hits), "samples": hits[:3]}
        except Unsupported as e: creal[fn] = {"unsupported": str(e)}
    json.dump(creal, open("tests/results/correlation_real.json", "w"), indent=1, default=str)

    print(f"Corpus: {len(files)} files, {total} events ({bad} unparseable lines)")
    print(f"{'Rule':<56s}{'Matches':>8s}")
    for fn, n in counts.items(): print(f"{fn:<56s}{n:>8d}")
    for fn, why in skipped.items(): print(f"{fn:<56s}  UNSUPPORTED ({why})")
    print("\nCorrelation rules on real corpus:")
    for fn, r in creal.items(): print(f"  {fn:<62s} {r.get('hits', r.get('unsupported'))}")
    print("\nWrote tests/results/effectiveness.json, effectiveness_evidence.json, correlation_real.json")

if __name__ == "__main__": main()
