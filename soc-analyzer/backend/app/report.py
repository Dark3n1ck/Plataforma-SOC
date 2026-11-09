"""Informe PDF profesional, limitado a la investigación activa."""
import io
import re
from collections import OrderedDict
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Line, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import CondPageBreak, KeepTogether, NextPageTemplate, PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle, BaseDocTemplate, Frame

from . import rules, service

NAVY = colors.HexColor("#14202E")
TEAL = colors.HexColor("#0F7F73")
GREY = colors.HexColor("#566474")
LINE = colors.HexColor("#CBD4DE")
SOFT = colors.HexColor("#EEF2F6")
SEV = {"Crítico": "#B3202C", "Alto": "#C2620E", "Medio": "#8A6D00", "Bajo": "#1F6AA5"}
SEV_BG = {"Crítico": "#FBE3E5", "Alto": "#FCEBD9", "Medio": "#FBF3CC", "Bajo": "#DCEBF7"}
MONTHS = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"]
ALL_SECTIONS = ["summary", "scope", "incidents", "timeline", "correlation", "mitre", "dangerous", "actions", "iocs", "evidence"]

S = {
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9.6, leading=14, textColor=NAVY, spaceAfter=6, alignment=TA_LEFT),
    "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8, leading=11, textColor=GREY),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=NAVY, spaceBefore=4, spaceAfter=9),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=12, leading=16, textColor=NAVY, spaceBefore=10, spaceAfter=5),
    "h3": ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=9.6, leading=13, textColor=TEAL, spaceBefore=7, spaceAfter=3),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=7.8, leading=10.2, textColor=NAVY),
    "cellb": ParagraphStyle("cellb", fontName="Helvetica-Bold", fontSize=7.8, leading=10.2, textColor=NAVY),
    "head": ParagraphStyle("head", fontName="Helvetica-Bold", fontSize=7.6, leading=10, textColor=colors.white),
    "mono": ParagraphStyle("mono", fontName="Courier", fontSize=7.4, leading=9.8, textColor=NAVY),
    "bullet": ParagraphStyle("bullet", fontName="Helvetica", fontSize=9.6, leading=13.5, textColor=NAVY, leftIndent=11, bulletIndent=1, spaceAfter=3),
}

ACTIONS = {
    "spray": [("Inmediata", "Restablecer la contraseña de {users}, revocar sus sesiones y bloquear {ips}.", "Identidades y Accesos", "La cuenta pierde el acceso hasta validar a su titular."),
              ("24 horas", "Forzar el cambio de contraseña en las cuentas atacadas y activar MFA en el acceso remoto.", "Identidades y Accesos", "Requiere comunicar el cambio a los usuarios.")],
    "lateral": [("Inmediata", "Deshabilitar {users}, aislar {hosts} tras preservar evidencia y bloquear {ips}.", "SOC / Infraestructura", "Interrumpe los servicios de esos servidores; se revierte al validar la limpieza."),
                ("24 horas", "Retirar la exposición directa de RDP y exigir VPN con MFA.", "Infraestructura", "Cambia la forma de acceso de los administradores.")],
    "impact": [("Inmediata", "Aislar los equipos {hosts}, suspender {users} y verificar copias de seguridad fuera de línea.", "SOC / Infraestructura", "Detiene las tareas que dependan de esa cuenta."),
               ("24 horas", "Buscar comandos de eliminación de copias en todos los equipos y separar las cuentas de respaldo por función.", "SOC", "Sin impacto en el servicio.")],
    "exfil": [("Inmediata", "Bloquear los destinos externos, suspender {users} y aislar {hosts}.", "SOC / Redes", "Afecta el trabajo del usuario hasta cerrar la validación."),
              ("24-72 horas", "Determinar los datos enviados e informar a Legal para evaluar la notificación.", "Legal / Seguridad", "Puede activar obligaciones legales."),
              ("30 días", "Implementar DLP y límites de carga en el proxy.", "Seguridad / Redes", "Requiere ajustes para evitar falsos positivos.")],
    "persist": [("Inmediata", "Preservar y eliminar la tarea y el servicio, y suspender {users}.", "SOC / Infraestructura", "Se revierte restaurando la tarea exportada."),
                ("24 horas", "Buscar los mismos indicadores en todos los servidores.", "SOC", "Sin impacto en el servicio.")],
    "web": [("Inmediata", "Aislar {hosts} tras preservar memoria y disco, bloquear {ips} y retirar la webshell.", "SOC / Aplicaciones", "El sitio queda fuera de servicio durante la contención."),
            ("24-72 horas", "Rotar secretos, corregir la carga de archivos e impedir la ejecución en la carpeta de subidas.", "Aplicaciones", "Requiere una ventana de despliegue.")],
    "generic": [("24 horas", "Validar la actividad con el responsable del sistema.", "SOC", "Sin impacto en el servicio.")],
}
HARDENING = [
    ("30 días", "Corregir la severidad en el SIEM para accesos externos exitosos, compresión de datos y ejecución repetida desde rutas sospechosas.", "SOC", "Aumenta las alertas al inicio; requiere ajuste."),
    ("30 días", "Centralizar el inventario de equipos e IP para atribuir cada origen interno a un activo.", "Infraestructura", "Sin impacto en el servicio."),
    ("30 días", "Registrar el volumen transferido en firewall y el contenido completo de PowerShell.", "SOC / Redes", "Mayor volumen de logs."),
]


def e(v):
    return escape("" if v is None else str(v))


def P(text, style="cell"):
    return Paragraph(text, S[style])


def fdate(ts):
    return f"{int(ts[8:10])}-{MONTHS[int(ts[5:7]) - 1]}-{ts[:4]}" if ts else ""


def sev_tag(s):
    return f'<font color="{SEV[s]}"><b>{e(s)}</b></font>'


def table(rows, widths, extra=None, header=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0, splitByRow=1)
    st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.35, LINE), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5)]
    if header:
        st.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    t.setStyle(TableStyle(st + (extra or [])))
    return t


def head(*names):
    return [P(e(n), "head") for n in names]


def scope(con, inv, min_severity="Alto"):
    if min_severity not in rules.SEV_RANK:
        min_severity = "Alto"
    fs = service.findings(con, inv)
    incs = service.incidents(con, inv, fs)
    level = rules.SEV_RANK[min_severity]
    chosen = [i for i in incs if i["rank"] >= level]
    ids = {i["id"] for i in chosen}
    loose = [f for f in fs if f["incident_id"] is None and f["rank"] >= level]
    included = [f for f in fs if f["incident_id"] in ids] + loose
    events = {ev["id"] for f in included for ev in f["events"]}
    return {"incidents": len(chosen), "findings": len(included), "events": len(events), "critical": sum(1 for f in included if f["severity"] == "Crítico"), "high": sum(1 for f in included if f["severity"] == "Alto"), "medium": sum(1 for f in included if f["severity"] == "Medio"), "low": sum(1 for f in included if f["severity"] == "Bajo")}


def compress_ids(events):
    ids = [ev.get("log_id") or str(ev["id"]) for ev in events]
    if len(ids) <= 3:
        return ", ".join(ids)
    return f"{ids[0]} ... {ids[-1]} ({len(ids)})"


def gantt(incs, width):
    t0 = min(service_ts(i["ts_start"]) for i in incs)
    t1 = max(service_ts(i["ts_end"]) for i in incs)
    span = max(t1 - t0, 60)
    rowh, left = 18, 58
    h = rowh * len(incs) + 24
    d = Drawing(width, h)
    usable = width - left - 12
    x = lambda v: left + (v - t0) / span * usable
    first = int(t0 // 1800 + 1) * 1800
    tick = first
    while tick <= t1:
        d.add(Line(x(tick), 16, x(tick), h, strokeColor=LINE, strokeWidth=0.35))
        if int((tick - first) / 1800) % 2 == 0:
            d.add(String(x(tick) - 11, 5, f"{int(tick // 3600):02d}:{int(tick % 3600 // 60):02d}", fontName="Helvetica", fontSize=7, fillColor=GREY))
        tick += 1800
    for n, i in enumerate(incs):
        y = h - rowh * (n + 1) + 2
        d.add(String(0, y + 3, i["code"], fontName="Helvetica-Bold", fontSize=7.8, fillColor=NAVY))
        a, b = service_ts(i["ts_start"]), service_ts(i["ts_end"])
        d.add(Rect(x(a), y, max(x(b) - x(a), 3), 11, fillColor=colors.HexColor(SEV[i["severity"]]), strokeColor=None))
    return d


def service_ts(ts):
    return int(ts[11:13]) * 3600 + int(ts[14:16]) * 60 + int(ts[17:19])


def iocs(fs):
    found = OrderedDict()

    def add(kind, value, code):
        found.setdefault((kind, value), set()).add(code)

    for f in fs:
        code = f.get("incident") or f["code"]
        for ev in f["events"]:
            for v in (ev.get("src_ip"), ev.get("dest")):
                if rules.is_external(v):
                    add("Dirección externa", v, code)
            c = ev.get("cmd") or ""
            if f["rule_id"] in ("R011",):
                for p in re.findall(r"[A-Za-z]:\\[^\s;*]+\.(?:zip|7z|rar)", c):
                    add("Archivo", p, code)
            if f["rule_id"] == "R013":
                m = re.search(r"TaskName=([^;]+)", c)
                if m:
                    add("Tarea programada", m.group(1), code)
                for p in re.findall(r"[A-Za-z]:\\[^\s;]+", c):
                    add("Archivo", p, code)
            if f["rule_id"] == "R014":
                m = re.search(r"ServiceName=([^;]+)", c)
                if m:
                    add("Servicio", m.group(1), code)
                for p in re.findall(r"[A-Za-z]:\\[^\s;]+", c):
                    add("Archivo", p, code)
            if f["rule_id"] == "R016":
                add("URL", c, code)
        if f["rule_id"] in ("R003", "R004", "R006", "R010", "R012", "R013", "R014", "R019") and f.get("primary_user"):
            add("Cuenta afectada", f["primary_user"], code)
    return [(k, v, ", ".join(sorted(codes))) for (k, v), codes in sorted(found.items())]


def build(con, inv, min_severity="Alto", sections=None, analyst="", organization=""):
    if min_severity not in rules.SEV_RANK:
        min_severity = "Alto"
    secs = [s for s in ALL_SECTIONS if sections is None or s in sections]
    info = service.investigation(con, inv)
    fs_all = service.findings(con, inv)
    incs_all = service.incidents(con, inv, fs_all)
    rels_all = service.relations(con, inv)
    level = rules.SEV_RANK[min_severity]
    incs = [i for i in incs_all if i["rank"] >= level]
    ids = {i["id"] for i in incs}
    codes = {i["code"] for i in incs}
    loose = [f for f in fs_all if f["incident_id"] is None and f["rank"] >= level]
    fs = [f for f in fs_all if f["incident_id"] in ids] + loose
    rels = [r for r in rels_all if r["a"] in codes and r["b"] in codes]
    evs_in = {ev["id"]: ev for f in fs for ev in f["events"]}
    W = A4[0] - 40 * mm
    story = []
    file0 = info["files"][0]
    period = f"{fdate(info['ts_min'])}, {info['ts_min'][11:]} a {info['ts_max'][11:]}" if info["ts_min"][:10] == info["ts_max"][:10] else f"{info['ts_min']} a {info['ts_max']}"

    # Portada
    story += [Spacer(1, 42 * mm), P('<font color="#0F7F73"><b>CONFIDENCIAL · USO INTERNO</b></font>', "body"), Spacer(1, 4),
              Paragraph("Informe de análisis de eventos de seguridad", ParagraphStyle("t", fontName="Helvetica-Bold", fontSize=25, leading=30, textColor=NAVY)), Spacer(1, 10),
              Paragraph("Eventos más peligrosos, correlación y medidas recomendadas", ParagraphStyle("st", fontName="Helvetica", fontSize=12.5, leading=17, textColor=GREY)), Spacer(1, 24 * mm)]
    meta = [("Organización", organization or "No indicada"), ("Analista", analyst or "No indicado"), ("Archivo analizado", " · ".join(f["filename"] for f in info["files"])), ("SHA-256", file0["sha256"]), ("Periodo de los eventos", period), ("Eventos importados", f"{info['total_events']}"), ("Severidad incluida", f"{min_severity} o superior"), ("Reglas", f"Versión {rules.RULES_VERSION}")]
    story += [table([[P(e(k), "cellb"), P(e(v), "mono" if k == "SHA-256" else "cell")] for k, v in meta], [42 * mm, W - 42 * mm], header=False), NextPageTemplate("body"), PageBreak()]

    crit = [i for i in incs if i["severity"] == "Crítico"]
    if "summary" in secs:
        sevc = {s: sum(1 for f in fs if f["severity"] == s) for s in rules.SEV_RANK}
        ext = sorted({ip for i in incs for ip in i["src_ips"] if rules.is_external(ip)})
        hosts = sorted({h for i in incs for h in i["hosts"]})
        story += [P("1. Resumen ejecutivo", "h1"),
                  P(f"Se analizaron <b>{info['total_events']} eventos</b> del {e(period)}. El análisis identificó <b>{len(incs)} incidentes</b>, de los cuales <b>{len(crit)} son críticos</b>, a partir de {len(fs)} hallazgos y {len(evs_in)} eventos de evidencia.", "body"),
                  P(f"La actividad afectó a {len(hosts)} equipos ({e(', '.join(hosts))}) y participaron {len(ext)} direcciones externas de origen. La organización debe tratar la situación como un compromiso activo hasta completar la contención y validar los puntos pendientes de este informe.", "body")]
        rows = [[P("Hallazgos críticos", "small"), P("Altos", "small"), P("Medios", "small"), P("Bajos", "small")], [P(f'<font size="18" color="{SEV["Crítico"]}"><b>{sevc["Crítico"]}</b></font>', "body"), P(f'<font size="18" color="{SEV["Alto"]}"><b>{sevc["Alto"]}</b></font>', "body"), P(f'<font size="18" color="{SEV["Medio"]}"><b>{sevc["Medio"]}</b></font>', "body"), P(f'<font size="18" color="{SEV["Bajo"]}"><b>{sevc["Bajo"]}</b></font>', "body")]]
        k = Table(rows, colWidths=[W / 4] * 4, rowHeights=[14, 30])
        k.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SOFT), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        story += [Spacer(1, 3), k, Spacer(1, 7), P("Incidentes identificados", "h2")]
        rows = [head("ID", "Sev.", "Qué ocurrió", "Dónde", "Desde dónde", "Hora")]
        for i in incs:
            rows.append([P(e(i["code"]), "cellb"), P(sev_tag(i["severity"])), P(e(i["title"])), P(e(", ".join(i["hosts"]))), P(e(", ".join(i["src_ips"]))), P(f"{i['ts_start'][11:16]} a {i['ts_end'][11:16]}")])
        story.append(table(rows, [15 * mm, 14 * mm, W - 15 * mm - 14 * mm - 32 * mm - 30 * mm - 18 * mm, 32 * mm, 30 * mm, 18 * mm]))
        if incs:
            story += [P("Línea de tiempo de los incidentes", "h2"), gantt(incs, W), P("El color indica la severidad del incidente: rojo crítico, naranja alto.", "small")]
            first = []
            for i in incs:
                ip_txt = ", ".join(ip for ip in i["src_ips"] if rules.is_external(ip)) or ", ".join(i["src_ips"])
                act = next((a for a in ACTIONS.get(i["analysis"].get("key"), []) if a[0] == "Inmediata"), None)
                if act:
                    first.append((i, act[1].format(users=", ".join(i["users"]) or "las cuentas implicadas", ips=ip_txt, hosts=", ".join(i["hosts"]))))
            if first:
                story.append(P("Qué atender primero", "h2"))
                story += [Paragraph(f"<b>{e(i['code'])}:</b> {e(t)}", S["bullet"], bulletText="•") for i, t in first]
        story.append(PageBreak())

    if "scope" in secs:
        q = info["quality"]
        cov = info["coverage"]
        info_hot = sum(1 for ev in evs_in.values() if (ev.get("severity_src") or "").lower().startswith("info"))
        story += [P("2. Alcance y limitaciones", "h1"), P("El análisis comprende únicamente los registros del archivo importado. No se consultaron los equipos ni otras fuentes. Los incidentes se construyen con reglas deterministas; cada conclusión remite a los registros originales.", "body"), P("Calidad de los datos", "h2")]
        bullets = []
        for raw, a in q.get("host_aliases", {}).items():
            bullets.append(f"Se unificó el equipo <b>{e(raw)}</b> con <b>{e(a['canonical'])}</b> ({a['count']} registros). Esta unificación supone que ambos nombres identifican al mismo equipo.")
        if q.get("redacted_values"):
            bullets.append(f"{q['redacted_values']} comandos codificados están anonimizados en el archivo, por lo que no se pudo analizar su contenido.")
        if info_hot:
            bullets.append(f"{info_hot} de los {len(evs_in)} eventos de evidencia venían clasificados como Informational en la fuente, entre ellos accesos y comandos relevantes para los ataques.")
        bullets += ["Las IP internas aparecen asociadas a muchos equipos y usuarios, por lo que una IP interna no basta para identificar al equipo de origen.", "El archivo no indica la zona horaria. Las horas se presentan tal como figuran en los registros.", "El registro de firewall no incluye bytes transferidos, de modo que esa conexión no permite medir el volumen enviado."]
        story += [Paragraph(b, S["bullet"], bulletText="•") for b in bullets]
        missing = [r for r in cov["rules"] if not r["evaluable"]]
        story.append(P(f"Cobertura: {cov['evaluable']} de {cov['total']} reglas fueron evaluables." + (" No se evaluaron: " + e(", ".join(r["name"] for r in missing)) + ", porque el archivo no contiene esos tipos de evento. La ausencia de hallazgos en ellas no descarta esa actividad." if missing else ""), "body"))
        story.append(Spacer(1, 8))

    if "incidents" in secs:
        story.append(P("3. Detalle de los incidentes", "h1"))
        for n, i in enumerate(incs):
            if n:
                story.append(CondPageBreak(95 * mm))
            mit = OrderedDict()
            for f in i["findings"]:
                for m in f["mitre"]:
                    mit[m["id"]] = f"{m['id']} {m['name']}"
            head_block = [P(f"{i['code']} · {e(i['title'])}", "h2"),
                table([[P("Severidad", "cellb"), P(sev_tag(i["severity"])), P("Hora", "cellb"), P(f"{fdate(i['ts_start'])}, {i['ts_start'][11:]} a {i['ts_end'][11:]}")],
                       [P("Dónde", "cellb"), P(e(", ".join(i["hosts"]))), P("Desde dónde", "cellb"), P(e(", ".join(i["src_ips"])))],
                       [P("Cuenta", "cellb"), P(e(", ".join(i["users"]) or "No identificada")), P("Eventos", "cellb"), P(str(len({ev["id"] for f in i["findings"] for ev in f["events"]})))]],
                      [20 * mm, W / 2 - 20 * mm, 22 * mm, W / 2 - 22 * mm], extra=[("BACKGROUND", (0, 0), (-1, -1), SOFT)], header=False),
                P("Qué hicieron", "h3")]
            story.append(KeepTogether(head_block + [Paragraph(e(i["findings"][0]["description"]), S["bullet"], bulletText="•")]))
            story += [Paragraph(e(f["description"]), S["bullet"], bulletText="•") for f in i["findings"][1:]]
            rows = [head("Hora", "ID", "Sev.", "Hallazgo", "Equipo", "Evento", "Registros")]
            for f in i["findings"]:
                eid = ", ".join(sorted({str(ev.get("event_id")) for ev in f["events"]}))
                rows.append([P(f["ts_start"][11:]), P(e(f["code"])), P(sev_tag(f["severity"])), P(e(f["title"])), P(e(", ".join(f["hosts"]))), P(e(eid)), P(e(compress_ids(f["events"])))])
            story += [P("Evidencia", "h3"), table(rows, [14 * mm, 11 * mm, 13 * mm, W - 14 * mm - 11 * mm - 13 * mm - 21 * mm - 25 * mm - 34 * mm, 21 * mm, 25 * mm, 34 * mm])]
            if i["context"]:
                story.append(P("Contexto: " + e("; ".join(f"{c['log_id']} ({c['ts'][11:]}, evento {c['event_id']}, {c['host']})" for c in i["context"][:6])) + ".", "small"))
            a = i["analysis"]
            story += [P("Correlación", "h3"), P(e("; ".join(f"{l['from']} y {l['to']}: {l['reason']} ({l['state'].lower()})" for l in i["links"])) + ".", "body"),
                      P("Valoración del analista", "h3"), P(f"<b>Hipótesis principal:</b> {e(a['hypothesis'])}", "body"), P(f"<b>Hipótesis alternativa:</b> {e(a['alternative'])}", "body"), P(f"<b>Pendiente de confirmar:</b> {e(a['pending'])}", "body"),
                      P(f"<b>MITRE ATT&amp;CK:</b> {e(', '.join(mit.values()))}", "body"), Spacer(1, 7)]
        story.append(PageBreak())

    if "timeline" in secs:
        rows = [head("Hora", "Incidente", "Sev.", "Equipo", "Usuario", "Origen", "Qué ocurrió")]
        for f in sorted(fs, key=lambda x: (x["ts_start"], x["code"])):
            rows.append([P(f["ts_start"][11:]), P(e(f.get("incident") or "-")), P(sev_tag(f["severity"])), P(e(", ".join(f["hosts"]))), P(e(f.get("primary_user") or ", ".join(f["users"][:2]) + ("..." if len(f["users"]) > 2 else ""))), P(e(", ".join(f["src_ips"]))), P(e(f["title"]))])
        story += [P("4. Cronología consolidada", "h1"), table(rows, [14 * mm, 15 * mm, 13 * mm, 20 * mm, 27 * mm, 25 * mm, W - 114 * mm]), PageBreak()]

    if "correlation" in secs:
        story += [P("5. Correlación entre incidentes", "h1"), P("Dentro de cada incidente, los eventos comparten IP, cuenta o equipo. Entre incidentes solo existen indicios: no hay evidencia suficiente para afirmar que todos correspondan al mismo actor.", "body")]
        if rels:
            rows = [head("Incidentes", "Relación", "Detalle", "Estado")]
            for r in rels:
                rows.append([P(f"{e(r['a'])} y {e(r['b'])}", "cellb"), P(e(r["kind"])), P(e(r["detail"])), P(e(r["state"]))])
            story.append(table(rows, [28 * mm, 28 * mm, W - 74 * mm, 18 * mm]))
        else:
            story.append(P("No se identificaron relaciones entre los incidentes incluidos.", "body"))
        story.append(Spacer(1, 10))

    if "mitre" in secs:
        rows = [head("Táctica", "Técnica", "Severidad máx.", "Hallazgos")]
        for t in service.mitre(fs):
            for x in t["techniques"]:
                rows.append([P(e(t["tactic"])), P(f"<b>{e(x['id'])}</b> {e(x['name'])}"), P(sev_tag(x["severity"])), P(e(", ".join(x["findings"])))])
        story += [CondPageBreak(60 * mm), P("6. Técnicas MITRE ATT&amp;CK observadas", "h1"), table(rows, [36 * mm, W - 36 * mm - 22 * mm - 42 * mm, 22 * mm, 42 * mm]), PageBreak()]

    if "dangerous" in secs:
        picked = [f for f in fs if f["rank"] >= 3]
        picked.sort(key=lambda f: (-f["rank"], f["ts_start"]))
        rows = [head("Registro", "Hora", "Sev.", "Evento", "Equipo", "Usuario", "IP de origen", "Detalle")]
        for f in picked:
            ev = next((x for x in reversed(f["events"]) if x.get("cmd")), f["events"][-1])
            detail = ev.get("cmd") if ev.get("cmd") and ev.get("cmd") != "powershell.exe" else ev.get("description")
            rows.append([P(e(ev.get("log_id"))), P(ev["ts"][11:]), P(sev_tag(f["severity"])), P(e(ev.get("event_id"))), P(e(ev.get("host"))), P(e(ev.get("user"))), P(e(ev.get("src_ip"))), P(e(detail))])
        story += [P("7. Eventos más peligrosos", "h1"), P("Se muestra un registro representativo de cada hallazgo crítico o alto, ordenados por severidad y hora.", "body"), table(rows, [17 * mm, 14 * mm, 13 * mm, 23 * mm, 18 * mm, 24 * mm, 22 * mm, W - 131 * mm]), PageBreak()]

    if "actions" in secs:
        rows = [head("Prioridad", "Incidente", "Medida", "Responsable", "Impacto o reversión")]
        order = {"Inmediata": 0, "24 horas": 1, "24-72 horas": 2, "30 días": 3}
        acts = []
        for i in incs:
            ext = ", ".join(ip for ip in i["src_ips"] if rules.is_external(ip)) or ", ".join(i["src_ips"])
            for pr, tx, own, imp in ACTIONS.get(i["analysis"].get("key"), ACTIONS["generic"]):
                acts.append((order[pr], pr, i["code"], tx.format(users=", ".join(i["users"]) or "las cuentas implicadas", ips=ext, hosts=", ".join(i["hosts"])), own, imp))
        acts += [(3, pr, "Todos", tx, own, imp) for pr, tx, own, imp in HARDENING]
        for _, pr, code, tx, own, imp in sorted(acts, key=lambda a: (a[0], a[2])):
            rows.append([P(e(pr), "cellb"), P(e(code)), P(e(tx)), P(e(own)), P(e(imp))])
        story += [P("8. Medidas recomendadas", "h1"), P("Antes de aislar o eliminar componentes, preserve la evidencia. Cada medida debe ser aprobada por el responsable del servicio afectado.", "body"), table(rows, [18 * mm, 15 * mm, W - 18 * mm - 15 * mm - 28 * mm - 44 * mm, 28 * mm, 44 * mm]), PageBreak()]

    if "iocs" in secs:
        rows = [head("Tipo", "Indicador", "Incidente")]
        for k, v, c in iocs(fs):
            rows.append([P(e(k)), P(e(v), "mono"), P(e(c))])
        story += [P("9. Indicadores de compromiso", "h1"), table(rows, [32 * mm, W - 32 * mm - 32 * mm, 32 * mm]), Spacer(1, 10)]

    if "evidence" in secs:
        rows = [head("Hallazgo", "Regla", "Título", "Registros de evidencia")]
        for f in sorted(fs, key=lambda x: x["code"]):
            rows.append([P(e(f["code"]), "cellb"), P(e(f["rule_id"])), P(e(f["title"])), P(e(", ".join(ev.get("log_id") or str(ev["id"]) for ev in f["events"])), "mono")])
        story += [CondPageBreak(60 * mm), P("Anexo. Registros de evidencia", "h1"), table(rows, [16 * mm, 13 * mm, 50 * mm, W - 79 * mm])]

    while story and isinstance(story[-1], PageBreak):
        story.pop()

    title = "Informe de análisis de eventos de seguridad"

    def cover(c, d):
        c.saveState()
        c.setFillColor(TEAL)
        c.rect(0, A4[1] - 6 * mm, A4[0], 6 * mm, stroke=0, fill=1)
        c.restoreState()

    def page(c, d):
        c.saveState()
        c.setStrokeColor(LINE)
        c.setLineWidth(0.5)
        c.line(20 * mm, A4[1] - 14 * mm, A4[0] - 20 * mm, A4[1] - 14 * mm)
        c.setFont("Helvetica", 7.8)
        c.setFillColor(GREY)
        c.drawString(20 * mm, A4[1] - 12 * mm, title)
        c.drawRightString(A4[0] - 20 * mm, A4[1] - 12 * mm, "Confidencial")
        c.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Página {d.page}")
        c.restoreState()

    buf = io.BytesIO()
    doc = BaseDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=20 * mm, bottomMargin=17 * mm, title=title, author=analyst or "Plataforma SOC")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate(id="cover", frames=[frame], onPage=cover), PageTemplate(id="body", frames=[frame], onPage=page)])
    doc.build(story)
    return buf.getvalue()
