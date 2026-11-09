"""Motor de detección determinista. Cada hallazgo explica su severidad y conserva sus evidencias."""
import ipaddress
import re
from collections import defaultdict
from datetime import datetime

SEV_RANK = {"Bajo": 1, "Medio": 2, "Alto": 3, "Crítico": 4}
RULES_VERSION = "1.0"
HTTP_IDS = {"HTTP_ACCESS"}
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]
SENSITIVE = re.compile(r"finance|finanzas|legal|rrhh|payroll|planilla|confidencial|confidential", re.I)
BAD_PATH = re.compile(r"\\programdata\\|\\temp\\|\\users\\public\\|\\appdata\\", re.I)


def ip_of(value):
    if not value:
        return None
    v = re.sub(r":\d+$", "", value.strip()) if value.count(":") == 1 else value.strip()
    try:
        return ipaddress.ip_address(v)
    except ValueError:
        return None


def is_external(value) -> bool:
    ip = ip_of(value)
    return ip is not None and not any(ip in n for n in _INTERNAL)


def dt(s):
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


def hhmm(s):
    return s[11:]


def text(e):
    return f"{e.get('description') or ''} {e.get('cmd') or ''}"


def is_fail(e):
    return e.get("event_id") == "4625"


def is_ok(e):
    return e.get("event_id") == "4624"


def logon_type(e):
    m = re.search(r"LogonType=(\d+)", e.get("description") or "")
    return m.group(1) if m else None


def clusters(events, gap_min):
    out, cur = [], []
    for e in events:
        if cur and (dt(e["ts"]) - dt(cur[-1]["ts"])).total_seconds() > gap_min * 60:
            out.append(cur)
            cur = []
        cur.append(e)
    if cur:
        out.append(cur)
    return out


def group(events, key):
    g = defaultdict(list)
    for e in events:
        g[key(e)].append(e)
    return g


def uniq(values):
    return sorted({v for v in values if v and v != "-"})


def plural(n, one, many):
    return f"{n} {one if n == 1 else many}"


def F(rule, title, sev, evs, desc, why, fix, mitre, primary=None, target=None, src=None, users=None):
    evs = sorted(evs, key=lambda e: e["ts"])
    return {
        "rule_id": rule, "title": title, "severity": sev, "events": evs, "description": desc, "why": list(why), "fix": list(fix), "mitre": mitre,
        "ts_start": evs[0]["ts"], "ts_end": evs[-1]["ts"],
        "src_ips": src if src is not None else uniq(e.get("src_ip") for e in evs),
        "users": users if users is not None else uniq(e.get("user") for e in evs),
        "hosts": uniq(e.get("host") for e in evs), "primary_user": primary, "target": target or ", ".join(uniq(e.get("host") for e in evs)),
    }


M = {
    "spray": ("T1110.003", "Password Spraying", "Acceso a credenciales"),
    "guess": ("T1110.001", "Password Guessing", "Acceso a credenciales"),
    "valid": ("T1078", "Valid Accounts", "Acceso inicial"),
    "valid_d": ("T1078.002", "Domain Accounts", "Escalada de privilegios"),
    "rdp": ("T1021.001", "Remote Desktop Protocol", "Movimiento lateral"),
    "smb": ("T1021.002", "SMB/Windows Admin Shares", "Movimiento lateral"),
    "ps": ("T1059.001", "PowerShell", "Ejecución"),
    "obf": ("T1027", "Obfuscated Files or Information", "Evasión de defensas"),
    "groups": ("T1069.001", "Local Groups", "Descubrimiento"),
    "shares": ("T1135", "Network Share Discovery", "Descubrimiento"),
    "share_data": ("T1039", "Data from Network Shared Drive", "Recolección"),
    "archive": ("T1560.001", "Archive via Utility", "Recolección"),
    "c2_exfil": ("T1041", "Exfiltration Over C2 Channel", "Exfiltración"),
    "https_exfil": ("T1048.002", "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", "Exfiltración"),
    "recovery": ("T1490", "Inhibit System Recovery", "Impacto"),
    "task": ("T1053.005", "Scheduled Task", "Persistencia"),
    "service": ("T1543.003", "Windows Service", "Persistencia"),
    "masq": ("T1036.004", "Masquerade Task or Service", "Evasión de defensas"),
    "svc_exec": ("T1569.002", "Service Execution", "Ejecución"),
    "webshell": ("T1505.003", "Web Shell", "Persistencia"),
    "public": ("T1190", "Exploit Public-Facing Application", "Acceso inicial"),
    "owner": ("T1033", "System Owner/User Discovery", "Descubrimiento"),
    "clear": ("T1070.001", "Clear Windows Event Logs", "Evasión de defensas"),
    "new_acct": ("T1136.001", "Local Account", "Persistencia"),
    "acct_manip": ("T1098", "Account Manipulation", "Persistencia"),
}

# id, nombre, ids de evento que permiten evaluarla (None = cualquier evento con línea de comandos/descripción)
CATALOG = [
    ("R001", "Password spraying", {"4625"}), ("R002", "Fuerza bruta contra una cuenta", {"4625"}),
    ("R003", "Inicio exitoso tras fallos", {"4624", "4625"}), ("R004", "Inicio exitoso desde IP externa", {"4624"}),
    ("R005", "Privilegios especiales en sesión sospechosa", {"4672"}), ("R006", "PowerShell codificado", {"4688"}),
    ("R007", "Reconocimiento con comandos nativos", {"4688", "4104"}), ("R008", "Movimiento lateral con cuenta comprometida", {"4624", "4625"}),
    ("R009", "Acceso a recurso compartido sensible", {"5140", "5145"}), ("R010", "Lectura masiva de archivos", {"4663"}),
    ("R011", "Compresión de datos con utilidad", {"4688"}), ("R012", "Eliminación de copias de recuperación", {"4688"}),
    ("R013", "Tarea programada sospechosa", {"4698"}), ("R014", "Servicio instalado en ruta sospechosa", {"7045"}),
    ("R015", "Ejecución repetida desde ruta sospechosa", {"4688"}), ("R016", "Petición a posible webshell", HTTP_IDS),
    ("R017", "Servidor web lanzó un intérprete", {"4688"}), ("R018", "Sondeo de rutas administrativas", HTTP_IDS),
    ("R019", "Envío masivo de datos al exterior", {"PROXY_ACCESS"}), ("R020", "Conexión saliente de un intérprete", {"5156"}),
    ("R021", "Privilegios especiales para validar", {"4672"}), ("R022", "Borrado del registro de auditoría", {"1102", "104"}),
    ("R023", "Creación de cuenta", {"4720"}), ("R024", "Alta en grupo privilegiado", {"4728", "4732", "4756"}),
]


def coverage(events):
    present = {e.get("event_id") for e in events}
    rows = [{"id": r, "name": n, "evaluable": bool(ids & present), "needs": sorted(ids)} for r, n, ids in CATALOG]
    return {"total": len(rows), "evaluable": sum(r["evaluable"] for r in rows), "rules": rows}


def analyze(events):
    fs = []
    fails = [e for e in events if is_fail(e) and e.get("src_ip")]
    oks = [e for e in events if is_ok(e) and e.get("src_ip")]

    # R001 Spraying
    spray_pairs = set()
    for ip, evs in group(fails, lambda e: e["src_ip"]).items():
        for c in clusters(evs, 10):
            users = uniq(e.get("user") for e in c)
            if len(c) >= 10 and len(users) >= 5:
                spray_pairs |= {(ip, u) for u in users}
                ext = is_external(ip)
                fs.append(F("R001", "Password spraying contra varias cuentas", "Alto", c,
                    f"Entre las {hhmm(c[0]['ts'])} y las {hhmm(c[-1]['ts'])}, la IP {ip} generó {len(c)} fallos de inicio de sesión contra {len(users)} cuentas en {', '.join(uniq(e.get('host') for e in c))}.",
                    ["Muchas cuentas distintas desde una misma IP en poco tiempo", "La IP es externa a la red corporativa" if ext else "Origen interno: valida el equipo emisor"],
                    ["Bloquear la IP de origen en el perímetro", "Forzar cambio de contraseña en las cuentas atacadas", "Exigir MFA en accesos remotos y restringir la exposición del servicio"],
                    [M["spray"]], target=", ".join(uniq(e.get("host") for e in c)), users=users))

    # R002 Fuerza bruta
    for (ip, user), evs in group(fails, lambda e: (e["src_ip"], e.get("user"))).items():
        if (ip, user) in spray_pairs or user in (None, "-"):
            continue
        ext = is_external(ip)
        for c in clusters(evs, 10):
            if len(c) >= (3 if ext else 10):
                rdp = any(logon_type(e) == "10" for e in c)
                fs.append(F("R002", f"Fuerza bruta contra {user}" + (" por RDP" if rdp else ""), "Alto" if ext else "Medio", c,
                    f"Entre las {hhmm(c[0]['ts'])} y las {hhmm(c[-1]['ts'])}, la IP {ip} falló {len(c)} veces al autenticarse como {user} en {c[0].get('host')}" + (" mediante RDP (LogonType 10)." if rdp else "."),
                    ["Fallos repetidos contra la misma cuenta"] + (["Origen externo"] if ext else []) + (["Servicio de acceso interactivo remoto"] if rdp else []),
                    ["Bloquear la IP de origen", "Retirar la exposición directa de RDP y usar VPN con MFA", "Revisar si hubo un inicio exitoso posterior"],
                    [M["guess"]], primary=user))

    # R003/R004 Accesos exitosos
    compromised = {}
    for e in oks:
        ip, user = e["src_ip"], e.get("user")
        prior = [f for f in fails if f["src_ip"] == ip and f.get("user") == user and 0 <= (dt(e["ts"]) - dt(f["ts"])).total_seconds() <= 1800]
        any_prior = [f for f in fails if f["src_ip"] == ip and 0 <= (dt(e["ts"]) - dt(f["ts"])).total_seconds() <= 1800]
        ext = is_external(ip)
        if len(any_prior) >= 3 and (ext or len(any_prior) >= 10) and prior:
            compromised[user] = e["ts"]
            fs.append(F("R003", f"Inicio exitoso de {user} tras fallos desde {ip}", "Crítico" if ext else "Alto", [e],
                f"A las {hhmm(e['ts'])}, {user} inició sesión correctamente en {e.get('host')} desde {ip}, después de {len(any_prior)} fallos de esa misma IP en los 30 minutos previos.",
                ["El ataque de credenciales tuvo éxito", "Origen externo con acceso válido al equipo" if ext else "Origen interno con patrón de adivinación"]
                + (["La fuente original lo marcó solo como Informational"] if (e.get("severity_src") or "").lower().startswith("info") else []),
                ["Deshabilitar la cuenta o restablecer su contraseña de inmediato", "Cerrar las sesiones activas y revisar Kerberos", "Revisar toda la actividad de la cuenta desde esa hora"],
                [M["valid"]], primary=user, target=f"{e.get('host')} · {user}"))
        elif ext:
            compromised.setdefault(user, e["ts"])
            fs.append(F("R004", f"Inicio exitoso desde IP externa ({ip})", "Alto", [e],
                f"A las {hhmm(e['ts'])}, {user} inició sesión en {e.get('host')} desde la IP externa {ip}.",
                ["Inicio de sesión directo desde fuera de la red"], ["Validar el acceso con el dueño de la cuenta", "Restringir el acceso remoto a VPN con MFA"],
                [M["valid"]], primary=user, target=f"{e.get('host')} · {user}"))

    # R005/R021 Privilegios especiales
    low = defaultdict(list)
    for e in (x for x in events if x.get("event_id") == "4672"):
        user, ip = e.get("user"), e.get("src_ip")
        t0 = compromised.get(user)
        recent = t0 is not None and 0 <= (dt(e["ts"]) - dt(t0)).total_seconds() <= 600
        if is_external(ip) or recent:
            fs.append(F("R005", f"Privilegios especiales para {user} desde {ip}", "Alto", [e],
                f"A las {hhmm(e['ts'])}, se asignaron privilegios especiales a {user} en {e.get('host')}, con origen {ip}.",
                ["La sesión proviene de un acceso sospechoso", "La cuenta opera con privilegios elevados"],
                ["Confirmar si la cuenta debe tener esos privilegios", "Revisar los procesos iniciados en esa sesión"], [M["valid_d"]], primary=user))
        elif user:
            low[user].append(e)
    for user, evs in low.items():
        fs.append(F("R021", f"Privilegios especiales de {user} para validar", "Bajo", evs,
            f"{user} recibió privilegios especiales {plural(len(evs), 'vez', 'veces')}, sin otros indicadores asociados.",
            ["Actividad frecuente en cuentas administrativas", "Sin indicadores de ataque asociados"],
            ["Confirmar que la cuenta pertenece a un grupo autorizado"], [M["valid_d"]], primary=user))

    # R006 PowerShell codificado
    for e in events:
        if re.search(r"powershell(\.exe)?\b.*\s-(enc|encodedcommand)\b", e.get("cmd") or "", re.I):
            user = e.get("user")
            comp = user in compromised
            fs.append(F("R006", f"PowerShell codificado en {e.get('host')}", "Alto", [e],
                f"A las {hhmm(e['ts'])}, {user} ejecutó PowerShell con un comando codificado en {e.get('host')}.",
                ["Los comandos codificados ocultan su contenido"] + (["La cuenta tiene un acceso sospechoso previo"] if comp else []),
                ["Recuperar el comando completo desde el endpoint o el log 4104", "Revisar el proceso padre y las conexiones de red", "Valorar el aislamiento del equipo si se confirma"],
                [M["ps"], M["obf"]], primary=user))

    # R007 Reconocimiento
    pat = re.compile(r"get-localgroupmember|get-smbshare|\bnet(\.exe)?\s+(view|group|localgroup|user)\b|\bnltest\b", re.I)
    for (user, host), evs in group([e for e in events if pat.search(text(e))], lambda e: (e.get("user"), e.get("host"))).items():
        for c in clusters(evs, 30):
            comp = user in compromised
            details = "; ".join(sorted({(e.get("cmd") if e.get("event_id") != "4104" else (e.get("description") or "").split(":", 1)[-1].strip()) or "" for e in c}))
            fs.append(F("R007", f"Reconocimiento desde {host}", "Alto" if comp else "Medio", c,
                f"Entre las {hhmm(c[0]['ts'])} y las {hhmm(c[-1]['ts'])}, {user} enumeró grupos o recursos desde {host}: {details}.",
                ["Comandos típicos de reconocimiento interno"] + (["La cuenta tiene un acceso sospechoso previo"] if comp else []),
                ["Confirmar si la tarea estaba autorizada", "Identificar qué sistemas se consultaron"], [M["groups"], M["shares"]], primary=user))

    # R008 Movimiento lateral
    net = [e for e in events if (is_ok(e) or is_fail(e)) and e.get("user") in compromised and logon_type(e) == "3" and e["ts"] >= compromised[e["user"]]]
    for (user, host), evs in group(net, lambda e: (e["user"], e.get("host"))).items():
        ok = [e for e in evs if is_ok(e)]
        m = re.search(r"source=([\w-]+)", evs[0].get("description") or "")
        origin = m.group(1) if m else evs[0].get("src_ip")
        fs.append(F("R008", f"Movimiento lateral de {origin} hacia {host}", "Alto" if ok else "Medio", evs,
            f"A las {hhmm(evs[0]['ts'])}, {user} intentó autenticarse en {host} desde {origin}" + (f" y lo consiguió a las {hhmm(ok[0]['ts'])}." if ok else ", sin éxito."),
            ["La cuenta ya tenía un acceso sospechoso", "Autenticación de red hacia otro servidor (LogonType 3)"],
            ["Contener el equipo de origen", "Revocar la sesión en el servidor de destino", "Limitar el uso de cuentas administrativas entre servidores"],
            [M["smb"]], primary=user, target=f"{host} · {user}"))

    # R009 Recursos sensibles
    sh = [e for e in events if e.get("event_id") in ("5140", "5145") and SENSITIVE.search(f"{e.get('dest') or ''} {e.get('description') or ''}")]
    for (user, host), evs in group(sh, lambda e: (e.get("user"), e.get("host"))).items():
        for c in clusters(evs, 30):
            names = uniq(re.search(r"(finance|finanzas|legal|rrhh|payroll|planilla|confidencial|confidential)[^\s]*", f"{e.get('dest') or ''} {e.get('description') or ''}", re.I).group(0) for e in c)
            fs.append(F("R009", f"Acceso a recurso sensible en {host}", "Alto" if user in compromised else "Medio", c,
                f"A las {hhmm(c[0]['ts'])}, {user} accedió en {host} a: {', '.join(names)}.",
                ["Recurso con información sensible"] + (["La cuenta tiene un acceso sospechoso previo"] if user in compromised else []),
                ["Confirmar si la cuenta debía acceder a ese recurso", "Revisar qué archivos se abrieron o copiaron"], [M["share_data"]], primary=user, target=f"{host} · {', '.join(names)}"))

    # R010 Lectura masiva
    obj = [e for e in events if e.get("event_id") == "4663" and e.get("dest")]
    for (user, dest), evs in group(obj, lambda e: (e.get("user"), e.get("dest"))).items():
        for c in clusters(evs, 5):
            if len(c) >= 10:
                sens = bool(SENSITIVE.search(dest))
                secs = int((dt(c[-1]["ts"]) - dt(c[0]["ts"])).total_seconds())
                fs.append(F("R010", f"Lectura masiva de archivos en {dest}", "Alto" if sens else "Medio", c,
                    f"Entre las {hhmm(c[0]['ts'])} y las {hhmm(c[-1]['ts'])}, {user} accedió a {len(c)} archivos de {dest}, a un ritmo regular de un archivo cada {round(secs / max(len(c) - 1, 1))} segundos.",
                    ["Acceso secuencial y automatizado"] + (["El recurso contiene información sensible"] if sens else []),
                    ["Comparar con las ventanas de respaldo autorizadas", "Confirmar el uso de la cuenta con su responsable", "Revisar si los archivos salieron de la red"],
                    [M["share_data"]], primary=user, target=dest))

    # R011 Compresión
    for e in events:
        if re.search(r"\b(tar(\.exe)?\s+.*-c|7z(\.exe)?\s+a\b|rar(\.exe)?\s+a\b|compress-archive|makecab)", e.get("cmd") or "", re.I):
            fs.append(F("R011", f"Compresión de datos en {e.get('host')}", "Alto", [e],
                f"A las {hhmm(e['ts'])}, {e.get('user')} comprimió datos en {e.get('host')} con el comando: {e.get('cmd')}.",
                ["Preparación habitual antes de extraer información"] + (["La fuente original lo marcó solo como Informational"] if (e.get("severity_src") or "").lower().startswith("info") else []),
                ["Localizar y preservar el archivo comprimido", "Determinar qué datos contiene", "Revisar las conexiones salientes posteriores"], [M["archive"]], primary=e.get("user")))

    # R012 Copias de recuperación
    for e in events:
        if re.search(r"vssadmin(\.exe)?\s+delete\s+shadows|wmic.*shadowcopy.*delete|wbadmin.*delete|bcdedit.*recoveryenabled\s+no", e.get("cmd") or "", re.I):
            fs.append(F("R012", f"Eliminación de copias de recuperación en {e.get('host')}", "Crítico", [e],
                f"A las {hhmm(e['ts'])}, {e.get('user')} ejecutó en {e.get('host')}: {e.get('cmd')}.",
                ["Técnica común antes de cifrar equipos con ransomware", "Reduce la capacidad de recuperación"],
                ["Aislar el equipo tras preservar evidencia", "Verificar copias de seguridad fuera de línea", "Buscar el mismo comando en otros equipos"], [M["recovery"]], primary=e.get("user")))

    # R013/R014 Persistencia
    for e in events:
        c = e.get("cmd") or ""
        if e.get("event_id") == "4698" and re.search(r"powershell|cmd\.exe|wscript|\\programdata\\|\\temp\\|\\users\\public\\", c, re.I):
            masq = "\\Microsoft\\Windows\\" in c
            fs.append(F("R013", f"Tarea programada sospechosa en {e.get('host')}", "Alto", [e],
                f"A las {hhmm(e['ts'])}, {e.get('user')} creó en {e.get('host')} la tarea: {c}.",
                ["La tarea ejecuta un script desde una ruta poco habitual"] + (["El nombre imita una tarea legítima de Windows"] if masq else []),
                ["Exportar y deshabilitar la tarea", "Analizar el script asociado", "Buscar la misma tarea en otros equipos"], [M["task"], M["masq"]] if masq else [M["task"]], primary=e.get("user")))
        if e.get("event_id") == "7045" and BAD_PATH.search(c):
            fs.append(F("R014", f"Servicio instalado en ruta sospechosa en {e.get('host')}", "Alto", [e],
                f"A las {hhmm(e['ts'])}, {e.get('user')} instaló en {e.get('host')} el servicio: {c}.",
                ["Un servicio estable no suele ejecutarse desde esa ruta", "El nombre imita un componente de actualización"],
                ["Preservar el ejecutable y calcular su hash", "Detener y eliminar el servicio tras recoger evidencia", "Buscar el mismo servicio en otros equipos"], [M["service"], M["masq"]], primary=e.get("user")))

    # R015 Ejecución repetida
    rep = [e for e in events if e.get("event_id") == "4688" and BAD_PATH.search(e.get("cmd") or "") and re.match(r'"?[a-z]:\\', e.get("cmd") or "", re.I)]
    for (cmd, host), evs in group(rep, lambda e: (e.get("cmd"), e.get("host"))).items():
        if len(evs) >= 3:
            gaps = {int((dt(b["ts"]) - dt(a["ts"])).total_seconds()) for a, b in zip(evs, evs[1:])}
            reg = len(gaps) == 1
            every = f", cada {gaps.copy().pop() // 60} minutos exactos" if reg else ""
            fs.append(F("R015", f"Ejecución repetida de {cmd.rsplit(chr(92), 1)[-1]}", "Alto", evs,
                f"Entre las {hhmm(evs[0]['ts'])} y las {hhmm(evs[-1]['ts'])}, {cmd} se ejecutó {len(evs)} veces en {host}{every}.",
                ["Ejecutable en una ruta poco habitual"] + (["El intervalo exacto indica automatización"] if reg else []) + (["La fuente original lo marcó solo como Informational"] if (evs[0].get("severity_src") or "").lower().startswith("info") else []),
                ["Analizar el ejecutable en un entorno aislado", "Revisar sus conexiones de red", "Eliminarlo junto con su mecanismo de persistencia"], [M["svc_exec"]], primary=evs[0].get("user")))

    # Web
    web = [e for e in events if e.get("event_id") in HTTP_IDS]
    shell_re = re.compile(r"\.(aspx?|php|jsp)\?.*\b(cmd|exec|command)=", re.I)
    shells = [e for e in web if shell_re.search(e.get("cmd") or "")]
    for (ip, host), evs in group(shells, lambda e: (e.get("src_ip"), e.get("host"))).items():
        codes = ", ".join(f"{sum(1 for e in evs if e.get('result') == r)} con {r}" for r in uniq(e.get("result") for e in evs))
        fs.append(F("R016", f"Peticiones a posible webshell en {host}", "Alto", evs,
            f"Entre las {hhmm(evs[0]['ts'])} y las {hhmm(evs[-1]['ts'])}, la IP {ip} solicitó {len(evs)} veces {evs[0].get('cmd')} en {host} (respuestas: {codes}).",
            ["La URL pasa un comando a un script ubicado en una carpeta de subidas"], ["Preservar los logs y el directorio web", "Localizar y retirar el archivo", "Corregir la subida de archivos que lo permitió"], [M["webshell"]], target=host))
    probe = [e for e in web if is_external(e.get("src_ip")) and e not in shells and re.search(r"/admin|/login|/api/.*export|wp-admin|phpmyadmin", e.get("cmd") or "", re.I)]
    for (ip, host), evs in group(probe, lambda e: (e.get("src_ip"), e.get("host"))).items():
        for c in clusters(evs, 10):
            if len(c) >= 10:
                paths = ", ".join(uniq(e.get("cmd") for e in c))
                exp = sum(1 for e in c if "export" in (e.get("cmd") or "") and e.get("result") == "200")
                fs.append(F("R018", f"Sondeo de rutas administrativas en {host}", "Medio", c,
                    f"Entre las {hhmm(c[0]['ts'])} y las {hhmm(c[-1]['ts'])}, la IP {ip} realizó {len(c)} peticiones a {paths}." + (f" {plural(exp, 'petición', 'peticiones')} a la exportación de la API respondieron 200." if exp else ""),
                    ["Ritmo automatizado desde una IP externa", "Rutas administrativas y de exportación"], ["Bloquear la IP en el WAF", "Revisar qué devolvió la API de exportación", "Restringir las rutas administrativas"], [M["public"]], target=host))
    for e in events:
        if e.get("event_id") == "4688" and re.search(r"iis apppool|www-data|apache|nginx|tomcat", e.get("user") or "", re.I) and re.search(r"cmd(\.exe)?|powershell|/bin/(ba)?sh|whoami", e.get("cmd") or "", re.I):
            fs.append(F("R017", f"Servidor web lanzó un intérprete en {e.get('host')}", "Crítico", [e],
                f"A las {hhmm(e['ts'])}, la cuenta del servidor web {e.get('user')} ejecutó {e.get('cmd')} en {e.get('host')}, con origen {e.get('src_ip')}.",
                ["Confirma ejecución de comandos en el servidor", "El equipo está expuesto a internet"],
                ["Aislar el servidor tras preservar memoria y disco", "Retirar la webshell y corregir la vía de entrada", "Rotar los secretos accesibles desde la aplicación"], [M["webshell"], M["owner"]], primary=e.get("user"), target=e.get("host")))

    # R019 Envío masivo
    def bytes_of(e):
        m = re.search(r"bytes_out=(\d+)", e.get("cmd") or "")
        return int(m.group(1)) if m else 0
    up = [e for e in events if bytes_of(e) and is_external(e.get("dest"))]
    for (user, dest), evs in group(up, lambda e: (e.get("user"), e.get("dest"))).items():
        for c in clusters(evs, 5):
            total = sum(bytes_of(e) for e in c)
            if total >= 50_000_000:
                mb = total / 1_000_000
                fs.append(F("R019", f"Envío masivo de datos hacia {dest}", "Crítico" if total >= 100_000_000 else "Alto", c,
                    f"Entre las {hhmm(c[0]['ts'])} y las {hhmm(c[-1]['ts'])}, {user} envió desde {c[0].get('host')} {len(c)} solicitudes POST a {dest}, con {mb:.1f} MB en total. El proxy las permitió.",
                    ["Gran volumen hacia un destino externo", "Envío en fragmentos a intervalos regulares"],
                    ["Bloquear el destino en proxy y firewall", "Determinar qué datos salieron y su clasificación", "Evaluar las obligaciones legales de notificación"], [M["https_exfil"]], primary=user, target=dest))

    # R020 Salida de un intérprete
    for e in events:
        if e.get("event_id") == "5156" and is_external(e.get("dest")) and re.search(r"powershell|cmd\.exe|wscript|cscript|mshta", text(e), re.I):
            fs.append(F("R020", f"Conexión saliente de un intérprete hacia {e.get('dest')}", "Alto", [e],
                f"A las {hhmm(e['ts'])}, un intérprete de comandos de {e.get('host')} abrió una conexión saliente permitida hacia {e.get('dest')}.",
                ["Conexión externa iniciada por un intérprete"] + (["La cuenta tiene un acceso sospechoso previo"] if e.get("user") in compromised else []) + ["El registro no indica cuántos datos se transfirieron"],
                ["Bloquear el destino", "Obtener del firewall o proxy el volumen transferido", "Revisar los procesos que abrieron la conexión"], [M["c2_exfil"]], primary=e.get("user"), target=e.get("dest")))

    # R022-R024
    for e in events:
        eid = e.get("event_id")
        if eid in ("1102", "104"):
            fs.append(F("R022", f"Borrado del registro de auditoría en {e.get('host')}", "Crítico", [e], f"A las {hhmm(e['ts'])}, {e.get('user')} borró un registro de auditoría en {e.get('host')}.", ["Puede ocultar actividad previa"], ["Recuperar los logs centralizados"], [M["clear"]], primary=e.get("user")))
        elif eid == "4720":
            fs.append(F("R023", f"Creación de cuenta en {e.get('host')}", "Medio", [e], f"A las {hhmm(e['ts'])}, {e.get('user')} creó una cuenta en {e.get('host')}.", ["Puede ser persistencia"], ["Validar la solicitud de alta"], [M["new_acct"]], primary=e.get("user")))
        elif eid in ("4728", "4732", "4756"):
            fs.append(F("R024", f"Alta en grupo privilegiado en {e.get('host')}", "Alto", [e], f"A las {hhmm(e['ts'])}, {e.get('user')} añadió un miembro a un grupo en {e.get('host')}.", ["Otorga privilegios adicionales"], ["Validar el cambio y revertirlo si no está autorizado"], [M["acct_manip"]], primary=e.get("user")))

    fs.sort(key=lambda f: (f["ts_start"], -SEV_RANK[f["severity"]]))
    for i, f in enumerate(fs, 1):
        f["code"] = f"F-{i:02d}"
    return fs
