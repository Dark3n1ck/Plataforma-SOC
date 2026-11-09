"""Lectura segura de archivos, mapeo de columnas y normalización a un esquema común."""
import csv
import hashlib
import io
import json
import re
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone

MAX_UPLOAD = 200 * 1024 * 1024
MAX_XLSX_UNCOMPRESSED = 1024 * 1024 * 1024
MAX_ROWS = 1_000_000

FIELDS = [
    ("log_id", "ID del registro", False),
    ("ts", "Fecha y hora", True),
    ("host", "Equipo", False),
    ("event_id", "ID del evento", False),
    ("user", "Usuario", False),
    ("src_ip", "IP de origen", False),
    ("dest", "Destino / objetivo", False),
    ("log_source", "Fuente del log", False),
    ("description", "Descripción", False),
    ("cmd", "Process_CommandLine", False),
    ("result", "Resultado", False),
    ("severity_src", "Severidad original", False),
]

ALIASES = {
    "log_id": ["logid", "recordid", "eventrecordid", "id"],
    "ts": ["timestamp", "timecreated", "datetime", "date", "time", "fecha", "fechahora", "eventtime"],
    "host": ["hostname", "computer", "computername", "host", "agentname", "equipo", "device"],
    "event_id": ["eventid", "evtid", "datawinsystemeventid", "ruleid", "codigo"],
    "user": ["user", "username", "account", "subjectusername", "datawineventdatasubjectusername", "usuario", "datadstuser", "datasrcuser"],
    "src_ip": ["sourceip", "srcip", "ipaddress", "clientip", "datasrcip", "datawineventdataipaddress", "ipdeorigen", "ip"],
    "dest": ["destination", "dest", "dstip", "target", "destino", "datadstip"],
    "log_source": ["logsource", "channel", "provider", "source", "location", "fuente"],
    "description": ["eventdescription", "message", "description", "ruledescription", "descripcion", "fulllog"],
    "cmd": ["processcommandline", "commandline", "cmd", "datawineventdatacommandline", "url", "uri"],
    "result": ["result", "status", "outcome", "resultado"],
    "severity_src": ["severity", "level", "rulelevel", "severidad"],
}


class ImportError_(ValueError):
    pass


def norm_header(h) -> str:
    return re.sub(r"[^a-z0-9]", "", str(h or "").lower())


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _flatten(obj, prefix=""):
    out = {}
    for k, v in obj.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        elif isinstance(v, list):
            out[key] = ", ".join(str(x) for x in v)
        else:
            out[key] = v
    return out


def _read_csv(data: bytes):
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            text = data.decode(enc)
            break
        except UnicodeError:
            continue
    else:
        raise ImportError_("No se pudo determinar la codificación del CSV.")
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    return list(reader.fieldnames or []), list(reader)


def _read_xlsx(data: bytes):
    import openpyxl

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if sum(i.file_size for i in z.infolist()) > MAX_XLSX_UNCOMPRESSED:
                raise ImportError_("El Excel descomprimido supera el límite permitido.")
    except zipfile.BadZipFile as e:
        raise ImportError_("El archivo no es un XLSX válido.") from e
    wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    ws = wb[wb.sheetnames[0]]
    it = ws.iter_rows(values_only=True)
    try:
        header = [str(c) if c is not None else f"col_{i}" for i, c in enumerate(next(it))]
    except StopIteration:
        raise ImportError_("La hoja está vacía.")
    rows = [dict(zip(header, r)) for r in it if any(c is not None for c in r)]
    wb.close()
    return header, rows


def _read_json(data: bytes):
    text = data.decode("utf-8-sig")
    try:
        doc = json.loads(text)
        if isinstance(doc, dict):
            doc = next((doc[k] for k in ("events", "alerts", "data", "items") if isinstance(doc.get(k), list)), [doc])
    except json.JSONDecodeError:
        doc = [json.loads(l) for l in text.splitlines() if l.strip()]
    rows = [_flatten(d) for d in doc if isinstance(d, dict)]
    header = []
    for r in rows:
        for k in r:
            if k not in header:
                header.append(k)
    return header, rows


def read_table(filename: str, data: bytes):
    if len(data) > MAX_UPLOAD:
        raise ImportError_("El archivo supera el máximo de 200 MB.")
    if not data:
        raise ImportError_("El archivo está vacío.")
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    try:
        if ext in ("csv", "tsv", "txt", "log"):
            header, rows = _read_csv(data)
        elif ext in ("xlsx", "xlsm"):
            header, rows = _read_xlsx(data)
        elif ext in ("json", "ndjson", "jsonl"):
            header, rows = _read_json(data)
        else:
            raise ImportError_("Formato no admitido. Usa CSV, XLSX o JSON.")
    except ImportError_:
        raise
    except Exception as e:
        raise ImportError_(f"No se pudo leer el archivo: {type(e).__name__}.") from e
    if not rows:
        raise ImportError_("El archivo no contiene registros.")
    if len(rows) > MAX_ROWS:
        raise ImportError_("El archivo supera el máximo de 1.000.000 de registros.")
    return header, rows


def propose_mapping(header):
    by_norm = {norm_header(h): h for h in header}
    mapping = {}
    for field, names in ALIASES.items():
        mapping[field] = next((by_norm[n] for n in names if n in by_norm), None)
    return mapping


_TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d-%m-%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S")


def parse_ts(v):
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v.replace(microsecond=0, tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    s = str(v).strip()
    for f in _TS_FORMATS:
        try:
            return datetime.strptime(s[:19] if "T" in s or len(s) > 19 else s, f).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00").replace("+0000", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _clean(v):
    if v is None:
        return None
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    s = str(v).strip()
    return s or None


def normalize(rows, mapping):
    """Devuelve (eventos, calidad). No descarta datos válidos: conserva el registro original en raw."""
    if not mapping.get("ts"):
        raise ImportError_("Debes indicar qué columna contiene la fecha y hora.")
    events, rejected = [], 0
    for r in rows:
        ts = parse_ts(r.get(mapping["ts"]))
        if not ts:
            rejected += 1
            continue
        e = {f: (_clean(r.get(c)) if c else None) for f, c in mapping.items() if f != "ts"}
        e["ts"] = ts
        raw = json.dumps(r, ensure_ascii=False, default=str, sort_keys=True)
        e["raw"] = raw
        e["row_hash"] = hashlib.sha256(raw.encode()).hexdigest()
        events.append(e)

    # Unifica variantes de un mismo equipo (DC01 / DC-01) y deja constancia.
    groups = defaultdict(Counter)
    for e in events:
        if e.get("host"):
            groups[re.sub(r"[^A-Z0-9]", "", e["host"].upper())][e["host"]] += 1
    canon, aliases = {}, {}
    for variants in groups.values():
        winner = variants.most_common(1)[0][0]
        for v in variants:
            canon[v] = winner
            if v != winner:
                aliases[v] = {"canonical": winner, "count": variants[v]}
    for e in events:
        e["host_raw"] = e.get("host")
        if e.get("host"):
            e["host"] = canon[e["host"]]
    seen, unique = set(), []
    for e in events:
        if e["row_hash"] not in seen:
            seen.add(e["row_hash"])
            unique.append(e)
    unique.sort(key=lambda x: x["ts"])
    missing = [label for f, label, _ in FIELDS if not mapping.get(f)]
    return unique, {
        "rejected_rows": rejected,
        "duplicate_rows": len(events) - len(unique),
        "host_aliases": aliases,
        "missing_fields": missing,
        "redacted_values": sum(1 for e in unique if re.search(r"redacted", e.get("cmd") or "", re.I)),
        "imported_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
