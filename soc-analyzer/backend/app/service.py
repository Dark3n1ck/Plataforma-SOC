"""Orquesta el análisis y las consultas por investigación."""
import json
from collections import Counter
from datetime import datetime, timezone

from . import correlate, ingest, rules

ALERT_RANK = rules.SEV_RANK
COLS = ["source", "row_hash", "log_id", "ts", "host", "host_raw", "event_id", "user", "src_ip", "dest", "log_source", "description", "cmd", "result", "severity_src", "raw"]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def create_or_extend(con, filename, data, mapping, name=None, add_to=None):
    header, rows = ingest.read_table(filename, data)
    unknown = [c for c in mapping.values() if c and c not in header]
    if unknown:
        raise ingest.ImportError_(f"Columna no encontrada: {unknown[0]}.")
    events, quality = ingest.normalize(rows, mapping)
    if add_to:
        cur = con.execute("SELECT id, quality FROM investigations WHERE id=?", (add_to,)).fetchone()
        if not cur:
            raise ingest.ImportError_("La investigación indicada no existe.")
        inv = cur["id"]
        old = json.loads(cur["quality"])
        quality["host_aliases"] = {**old.get("host_aliases", {}), **quality["host_aliases"]}
    else:
        c = con.execute("INSERT INTO investigations(name,created_at) VALUES(?,?)", (name or filename, now()))
        inv = c.lastrowid
    before = con.execute("SELECT COUNT(*) n FROM events WHERE investigation_id=?", (inv,)).fetchone()["n"]
    sql = f"INSERT OR IGNORE INTO events(investigation_id,{','.join(COLS)}) VALUES(?,{','.join('?' * len(COLS))})"
    con.executemany(sql, [[inv] + [e.get(k) if k != "source" else "import" for k in COLS] for e in events])
    con.execute("INSERT INTO files(investigation_id,filename,sha256,imported_at,row_count,mapping) VALUES(?,?,?,?,?,?)", (inv, filename, ingest.sha256(data), now(), len(rows), json.dumps(mapping)))
    after = con.execute("SELECT COUNT(*) n FROM events WHERE investigation_id=?", (inv,)).fetchone()["n"]
    quality["added_rows"] = after - before
    analyze(con, inv, quality)
    con.commit()
    return inv


def analyze(con, inv, quality):
    for t in ("findings", "incidents", "relations"):
        con.execute(f"DELETE FROM {t} WHERE investigation_id=?", (inv,))
    con.execute("UPDATE events SET alert_severity=NULL, alert_rank=0 WHERE investigation_id=?", (inv,))
    events = [dict(r) for r in con.execute("SELECT * FROM events WHERE investigation_id=? ORDER BY ts,id", (inv,))]
    findings = rules.analyze(events)
    incidents, rels = correlate.build(findings)
    correlate.add_context(incidents, findings, events)
    pk = {e["row_hash"]: e["id"] for e in events}
    inc_pk = {}
    for i in incidents:
        analysis = {**i["analysis"], "context": [pk[h] for h in i["context"]], "key": i["key"]}
        cur = con.execute("INSERT INTO incidents(investigation_id,code,title,severity,rank,ts_start,ts_end,hosts,users,src_ips,narrative,links,analysis) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (inv, i["code"], i["title"], i["severity"], ALERT_RANK[i["severity"]], i["ts_start"], i["ts_end"], json.dumps(i["hosts"]), json.dumps(i["users"]), json.dumps(i["src_ips"]), json.dumps(i["narrative"], ensure_ascii=False), json.dumps(i["links"], ensure_ascii=False), json.dumps(analysis, ensure_ascii=False)))
        inc_pk[i["code"]] = cur.lastrowid
    best = {}
    for f in findings:
        cur = con.execute("INSERT INTO findings(investigation_id,code,rule_id,title,severity,rank,description,why,fix,mitre,ts_start,ts_end,src_ips,users,hosts,primary_user,target,incident_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (inv, f["code"], f["rule_id"], f["title"], f["severity"], ALERT_RANK[f["severity"]], f["description"], json.dumps(f["why"], ensure_ascii=False), json.dumps(f["fix"], ensure_ascii=False), json.dumps(f["mitre"], ensure_ascii=False), f["ts_start"], f["ts_end"], json.dumps(f["src_ips"]), json.dumps(f["users"]), json.dumps(f["hosts"]), f.get("primary_user"), f.get("target"), inc_pk.get(f.get("incident"))))
        for e in f["events"]:
            con.execute("INSERT OR IGNORE INTO finding_events VALUES(?,?)", (cur.lastrowid, pk[e["row_hash"]]))
            if ALERT_RANK[f["severity"]] > best.get(pk[e["row_hash"]], (0, ""))[0]:
                best[pk[e["row_hash"]]] = (ALERT_RANK[f["severity"]], f["severity"])
    con.executemany("UPDATE events SET alert_rank=?, alert_severity=? WHERE id=?", [(r, s, i) for i, (r, s) in best.items()])
    for r in rels:
        con.execute("INSERT INTO relations(investigation_id,a,b,kind,detail,state) VALUES(?,?,?,?,?,?)", (inv, r["a"], r["b"], r["kind"], r["detail"], r["state"]))
    con.execute("UPDATE investigations SET ts_min=?, ts_max=?, total_events=?, quality=?, coverage=? WHERE id=?",
        (events[0]["ts"], events[-1]["ts"], len(events), json.dumps(quality, ensure_ascii=False), json.dumps(rules.coverage(events), ensure_ascii=False), inv))


def _f(r, con=None):
    d = dict(r)
    for k in ("why", "fix", "mitre", "src_ips", "users", "hosts"):
        d[k] = json.loads(d[k] or "[]")
    d["mitre"] = [{"id": m[0], "name": m[1], "tactic": m[2]} for m in d["mitre"]]
    return d


def investigation(con, inv):
    r = con.execute("SELECT * FROM investigations WHERE id=?", (inv,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["quality"], d["coverage"] = json.loads(d["quality"]), json.loads(d["coverage"])
    d["files"] = [dict(x) for x in con.execute("SELECT filename, sha256, imported_at, row_count FROM files WHERE investigation_id=? ORDER BY id", (inv,))]
    return d


def findings(con, inv):
    out = []
    code = {r["id"]: r["code"] for r in con.execute("SELECT id, code FROM incidents WHERE investigation_id=?", (inv,))}
    for r in con.execute("SELECT * FROM findings WHERE investigation_id=? ORDER BY rank DESC, ts_start", (inv,)):
        d = _f(r)
        d["incident"] = code.get(d["incident_id"])
        d["events"] = [dict(e) for e in con.execute("SELECT e.id,e.log_id,e.ts,e.host,e.event_id,e.user,e.src_ip,e.dest,e.description,e.cmd,e.result,e.severity_src FROM events e JOIN finding_events fe ON fe.event_pk=e.id WHERE fe.finding_id=? ORDER BY e.ts,e.id", (d["id"],))]
        out.append(d)
    return out


def incidents(con, inv, fs=None):
    fs = fs if fs is not None else findings(con, inv)
    out = []
    for r in con.execute("SELECT * FROM incidents WHERE investigation_id=? ORDER BY ts_start", (inv,)):
        d = dict(r)
        for k in ("hosts", "users", "src_ips", "narrative", "links", "analysis"):
            d[k] = json.loads(d[k])
        d["findings"] = sorted([f for f in fs if f["incident_id"] == d["id"]], key=lambda f: (f["ts_start"], f["code"]))
        ids = d["analysis"].pop("context", [])
        d["context"] = [dict(e) for e in con.execute(f"SELECT id,log_id,ts,host,event_id,user,src_ip,dest,description,cmd,result FROM events WHERE id IN ({','.join('?' * len(ids))}) ORDER BY ts", ids)] if ids else []
        out.append(d)
    return out


def relations(con, inv):
    return [dict(r) for r in con.execute("SELECT a,b,kind,detail,state FROM relations WHERE investigation_id=? ORDER BY a,b", (inv,))]


def mitre(fs):
    tactics = {}
    for f in fs:
        for m in f["mitre"]:
            t = tactics.setdefault(m["tactic"], {})
            x = t.setdefault(m["id"], {**m, "count": 0, "rank": 0, "severity": "Bajo", "findings": []})
            x["count"] += 1
            x["findings"].append(f["code"])
            if f["rank"] > x["rank"]:
                x["rank"], x["severity"] = f["rank"], f["severity"]
    order = ["Acceso inicial", "Ejecución", "Persistencia", "Escalada de privilegios", "Evasión de defensas", "Acceso a credenciales", "Descubrimiento", "Movimiento lateral", "Recolección", "Comando y control", "Exfiltración", "Impacto"]
    return [{"tactic": t, "techniques": sorted(tactics[t].values(), key=lambda x: x["id"]), "count": sum(x["count"] for x in tactics[t].values())} for t in order if t in tactics]


def dashboard(con, inv):
    q = lambda s, *a: con.execute(s, (inv, *a)).fetchall()
    info = investigation(con, inv)
    fs = findings(con, inv)
    incs = incidents(con, inv, fs)
    sev = Counter(f["severity"] for f in fs)
    in_finding = q("SELECT COUNT(*) n FROM events WHERE investigation_id=? AND alert_rank>0")[0]["n"]
    buckets = {}
    for r in q("SELECT ts, alert_rank FROM events WHERE investigation_id=?"):
        minute = int(r["ts"][14:16])
        k = f"{r['ts'][:14]}{minute - minute % 30:02d}"
        b = buckets.setdefault(k, {"t": k, "normal": 0, "hot": 0})
        b["hot" if r["alert_rank"] else "normal"] += 1
    top = lambda col, where="": [dict(k=r["k"], v=r["v"]) for r in q(f"SELECT {col} k, COUNT(*) v FROM events WHERE investigation_id=? AND {col} IS NOT NULL AND {col}!='-' {where} GROUP BY {col} ORDER BY v DESC, k LIMIT 6")]
    hot = "AND alert_rank>0"
    return {
        "investigation": info,
        "kpis": {"events": info["total_events"], "findings": len(fs), "critical": sev["Crítico"], "high": sev["Alto"], "medium": sev["Medio"], "low": sev["Bajo"], "incidents": len(incs), "in_finding": in_finding,
                 "hosts_hot": len({h for f in fs for h in f["hosts"]}), "hosts": q("SELECT COUNT(DISTINCT host) n FROM events WHERE investigation_id=?")[0]["n"],
                 "users_hot": len({u for f in fs for u in f["users"]}), "users": q("SELECT COUNT(DISTINCT user) n FROM events WHERE investigation_id=? AND user!='-'")[0]["n"],
                 "sources": q("SELECT COUNT(DISTINCT log_source) n FROM events WHERE investigation_id=?")[0]["n"]},
        "timeline": [buckets[k] for k in sorted(buckets)],
        "tactics": [{"tactic": t["tactic"], "count": t["count"]} for t in mitre(fs)],
        "tops": {"src_ip": top("src_ip", hot), "event_id": top("event_id"), "host": top("host", hot), "user": top("user", hot)},
        "source_severity": [dict(k=r["k"], v=r["v"]) for r in q("SELECT severity_src k, COUNT(*) v FROM events WHERE investigation_id=? GROUP BY severity_src ORDER BY v DESC")],
        "incidents": [{k: i[k] for k in ("code", "title", "severity", "ts_start", "ts_end", "hosts")} | {"alerts": len(i["findings"])} for i in incs],
    }
