"""Agrupa hallazgos en incidentes y explica qué une a cada uno."""
import ipaddress
from datetime import datetime

from .rules import SEV_RANK, is_external, ip_of

WINDOW = 3600


def _dt(s):
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


def _ext(f):
    return {i for i in f["src_ips"] if is_external(i)}


def _delta(a, b):
    return abs((_dt(b["ts_start"]) - _dt(a["ts_end"])).total_seconds())


def _linked(a, b):
    shared_ip = _ext(a) & _ext(b)
    if shared_ip:
        return True
    u = a.get("primary_user")
    return bool(u and u != "-" and u == b.get("primary_user") and _delta(a, b) <= WINDOW)


def _title(rules, f):
    host = lambda r: next((x["hosts"][0] for x in f if x["rule_id"] == r), "")
    if "R017" in rules or "R016" in rules:
        return "web", f"Compromiso del servidor web {host('R017') or host('R016')} mediante webshell"
    if "R008" in rules:
        return "lateral", f"Compromiso remoto de {host('R003') or host('R004')} y movimiento lateral hacia {host('R008')}"
    if "R012" in rules:
        return "impact", "Acceso masivo a datos y eliminación de copias de recuperación"
    if "R019" in rules:
        return "exfil", f"Extracción de datos desde {host('R019')}"
    if "R001" in rules and "R003" in rules:
        return "spray", "Password spraying con acceso exitoso"
    if "R013" in rules or "R014" in rules:
        return "persist", f"Persistencia en {host('R013') or host('R014')}"
    return "generic", f[0]["title"]


ANALYSIS = {
    "spray": ("Un actor externo obtuvo credenciales válidas mediante password spraying.", "Un usuario legítimo se conectó desde esa IP por coincidencia, lo cual es poco probable tras el patrón de fallos.", "Confirmar con el usuario el acceso y revisar el registro de autenticación completo del controlador de dominio."),
    "lateral": ("Un actor externo tomó control de la cuenta por RDP, se desplazó al servidor de archivos y preparó datos para extraerlos.", "Un administrador trabajó de forma remota sin seguir el procedimiento, aunque el patrón completo lo hace poco probable.", "Obtener el contenido del comando codificado, ubicar el archivo comprimido y medir el volumen enviado al destino externo."),
    "impact": ("La cuenta fue usada para recoger datos y reducir la capacidad de recuperación, como preparación de un ataque de impacto.", "Un proceso de respaldo mal configurado explicaría el acceso a archivos, pero no la eliminación de copias de recuperación.", "Confirmar con el responsable de la cuenta si existía una tarea programada y recuperar el comando codificado."),
    "exfil": ("Se comprimió información sensible y se envió fuera de la organización.", "Una carga autorizada a un proveedor externo, si existe un contrato o ticket que la respalde.", "Identificar la empresa dueña del destino y confirmar con el usuario si realizó la operación."),
    "persist": ("Un actor instaló persistencia disfrazada de componente de actualización.", "Una instalación administrativa legítima, lo cual se descarta si no existe un cambio aprobado.", "Obtener el ejecutable y el script, calcular sus hashes y revisar sus conexiones."),
    "web": ("Un actor externo ejecutó comandos en el servidor mediante una webshell.", "Un escaneo de vulnerabilidades autorizado, que no explicaría por sí solo la ejecución de cmd.exe.", "Determinar cómo llegó el archivo al servidor y qué devolvió la API de exportación."),
    "generic": ("La actividad requiere validación por parte del analista.", "Actividad legítima no documentada.", "Validar con el responsable del sistema."),
}


def build(findings):
    candidates = [f for f in findings if SEV_RANK[f["severity"]] >= 2]
    parent = list(range(len(candidates)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i, a in enumerate(candidates):
        for j in range(i + 1, len(candidates)):
            if _linked(a, candidates[j]):
                parent[find(i)] = find(j)
    groups = {}
    for i, f in enumerate(candidates):
        groups.setdefault(find(i), []).append(f)

    incidents = []
    for fs in sorted(groups.values(), key=lambda x: min(f["ts_start"] for f in x)):
        fs.sort(key=lambda f: (f["ts_start"], f["code"]))
        if max(SEV_RANK[f["severity"]] for f in fs) < 3:
            continue
        rules = {f["rule_id"] for f in fs}
        key, title = _title(rules, fs)
        sev = max((f["severity"] for f in fs), key=lambda s: SEV_RANK[s])
        links = []
        for a, b in zip(fs, fs[1:]):
            shared = _ext(a) & _ext(b)
            mins = max(0, round((_dt(b["ts_start"]) - _dt(a["ts_end"])).total_seconds() / 60))
            if shared:
                links.append({"from": a["code"], "to": b["code"], "reason": f"Misma IP externa ({sorted(shared)[0]})", "state": "Confirmado"})
            else:
                same_host = set(a["hosts"]) & set(b["hosts"])
                u = a.get("primary_user") or b.get("primary_user")
                links.append({"from": a["code"], "to": b["code"], "reason": f"Misma cuenta ({u}), {mins} min después" + (f", en {sorted(same_host)[0]}" if same_host else ""), "state": "Confirmado" if same_host else "Relacionado"})
        n = len(incidents) + 1
        hyp, alt, pend = ANALYSIS[key]
        inc = {
            "code": f"INC-{n:02d}", "key": key, "title": title, "severity": sev, "ts_start": min(f["ts_start"] for f in fs), "ts_end": max(f["ts_end"] for f in fs),
            "hosts": sorted({h for f in fs for h in f["hosts"]}), "users": sorted({f["primary_user"] for f in fs if f.get("primary_user")}),
            "src_ips": sorted({i for f in fs for i in f["src_ips"] if is_external(i)}) or sorted({i for f in fs for i in f["src_ips"]}),
            "findings": fs, "links": links, "narrative": [f["description"] for f in fs],
            "analysis": {"hypothesis": hyp, "alternative": alt, "pending": pend},
        }
        for f in fs:
            f["incident"] = inc["code"]
        incidents.append(inc)
    return incidents, _relations(incidents)


def add_context(incidents, findings, events):
    """Eventos normales que completan la cadena: misma IP externa o misma sesión justo antes o después."""
    used = {e["row_hash"] for f in findings for e in f["events"]}
    for inc in incidents:
        ctx = []
        start, end = _dt(inc["ts_start"]), _dt(inc["ts_end"])
        keys = {(f["primary_user"], h, ip) for f in inc["findings"] for h in f["hosts"] for ip in f["src_ips"] if f.get("primary_user")}
        ext = {ip for ip in inc["src_ips"] if is_external(ip)}
        for e in events:
            if e["row_hash"] in used:
                continue
            t = _dt(e["ts"])
            near = -300 <= (t - start).total_seconds() and (t - end).total_seconds() <= 300
            if near and (e.get("src_ip") in ext or (e.get("user"), e.get("host"), e.get("src_ip")) in keys):
                ctx.append(e["row_hash"])
        inc["context"] = ctx


def _relations(incidents):
    rel = []
    spray = [i for i in incidents if any(f["rule_id"] == "R001" for f in i["findings"])]
    for s in spray:
        targets = {u for f in s["findings"] if f["rule_id"] == "R001" for u in f["users"]}
        for i in incidents:
            if i is s or i["ts_start"] < s["ts_start"]:
                continue
            common = sorted(targets & set(i["users"]))
            if common:
                rel.append({"a": s["code"], "b": i["code"], "kind": "Cuenta atacada", "detail": f"{', '.join(common)} fue objetivo del password spraying y luego aparece en {i['code']}. No hay un inicio exitoso desde la IP atacante para esa cuenta.", "state": "Posible"})
    for x in range(len(incidents)):
        for y in range(x + 1, len(incidents)):
            a, b = incidents[x], incidents[y]
            common = sorted(set(a["hosts"]) & set(b["hosts"]))
            if common:
                rel.append({"a": a["code"], "b": b["code"], "kind": "Mismo equipo", "detail": f"Ambos incidentes afectan a {', '.join(common)}.", "state": "Posible"})
            nets = lambda inc: {ipaddress.ip_network(f"{ip_of(v)}/24", strict=False) for f in inc["findings"] for v in f["src_ips"] + [f.get("target") or ""] if ip_of(v) and is_external(v) and ip_of(v).version == 4}
            same = sorted(str(n) for n in nets(a) & nets(b))
            if same:
                rel.append({"a": a["code"], "b": b["code"], "kind": "Misma red externa", "detail": f"Ambos usan direcciones de {', '.join(same)}. Es un indicio débil de infraestructura compartida.", "state": "Posible"})
    return rel
