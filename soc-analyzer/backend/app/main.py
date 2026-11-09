import csv
import io
import json
import re
from pathlib import Path
from urllib.parse import quote, urlparse

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import db, ingest, query, report, service

STATIC = Path(__file__).resolve().parent.parent / "static"
ALLOWED = ["127.0.0.1", "localhost", "testserver"]
app = FastAPI(title="Plataforma SOC", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED)
db.init()


@app.middleware("http")
async def security(request: Request, call_next):
    origin = request.headers.get("origin")
    if request.method not in ("GET", "HEAD") and origin and urlparse(origin).hostname not in ALLOWED:
        return JSONResponse({"detail": "Origen no permitido."}, status_code=403)
    resp = await call_next(request)
    resp.headers.update({
        "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    })
    return resp


def conn():
    return db.connect()


def need(con, inv):
    if not con.execute("SELECT 1 FROM investigations WHERE id=?", (inv,)).fetchone():
        raise HTTPException(404, "Investigación no encontrada.")


async def _read(file: UploadFile) -> bytes:
    data = await file.read(ingest.MAX_UPLOAD + 1)
    if len(data) > ingest.MAX_UPLOAD:
        raise HTTPException(413, "El archivo supera el máximo de 200 MB.")
    return data


@app.get("/api/meta")
def meta():
    return {"fields": [{"id": f, "label": l, "required": r} for f, l, r in ingest.FIELDS], "query_fields": sorted(query.FIELDS), "connectors": [{"id": "import", "name": "Archivos importados", "enabled": True}, {"id": "wazuh", "name": "Wazuh", "enabled": False}]}


@app.get("/api/investigations")
def list_investigations():
    con = conn()
    return [dict(r) for r in con.execute("SELECT i.id,i.name,i.created_at,i.ts_min,i.ts_max,i.total_events,(SELECT COUNT(*) FROM findings f WHERE f.investigation_id=i.id) findings FROM investigations i ORDER BY i.id DESC")]


@app.post("/api/imports/preview")
async def preview(file: UploadFile = File(...)):
    data = await _read(file)
    try:
        header, rows = ingest.read_table(file.filename or "archivo", data)
    except ingest.ImportError_ as e:
        raise HTTPException(400, str(e))
    digest = ingest.sha256(data)
    con = conn()
    dup = con.execute("SELECT i.id,i.name FROM files f JOIN investigations i ON i.id=f.investigation_id WHERE f.sha256=? ORDER BY i.id DESC", (digest,)).fetchone()
    sample = {h: next((str(r.get(h)) for r in rows if r.get(h) not in (None, "")), "") for h in header}
    return {"filename": file.filename, "sha256": digest, "rows": len(rows), "columns": header, "mapping": ingest.propose_mapping(header), "sample": sample, "duplicate": dict(dup) if dup else None}


@app.post("/api/investigations")
async def create(file: UploadFile = File(...), mapping: str = Form(...), name: str = Form(""), add_to: int | None = Form(None)):
    data = await _read(file)
    try:
        m = json.loads(mapping)
        if not isinstance(m, dict):
            raise ValueError
    except ValueError:
        raise HTTPException(400, "Mapeo no válido.")
    con = conn()
    try:
        inv = service.create_or_extend(con, file.filename or "archivo", data, m, name.strip()[:200] or None, add_to)
    except ingest.ImportError_ as e:
        con.rollback()
        raise HTTPException(400, str(e))
    return {"id": inv}


@app.delete("/api/investigations/{inv}")
def delete(inv: int):
    con = conn()
    need(con, inv)
    con.execute("DELETE FROM investigations WHERE id=?", (inv,))
    con.commit()
    return {"ok": True}


@app.get("/api/investigations/{inv}/dashboard")
def dashboard(inv: int):
    con = conn()
    need(con, inv)
    return service.dashboard(con, inv)


@app.get("/api/investigations/{inv}/findings")
def findings(inv: int):
    con = conn()
    need(con, inv)
    return service.findings(con, inv)


@app.get("/api/investigations/{inv}/incidents")
def incidents(inv: int):
    con = conn()
    need(con, inv)
    return {"incidents": service.incidents(con, inv), "relations": service.relations(con, inv)}


@app.get("/api/investigations/{inv}/mitre")
def mitre(inv: int):
    con = conn()
    need(con, inv)
    return service.mitre(service.findings(con, inv))


SORTABLE = {"ts", "event_id", "host", "user", "src_ip", "alert_rank"}
EV_COLS = "id,source,log_id,ts,host,event_id,user,src_ip,dest,log_source,description,cmd,result,severity_src,alert_severity,alert_rank"


def _where(inv, q, only):
    try:
        sql, params = query.compile_query(q)
    except query.QueryError as e:
        raise HTTPException(400, {"message": e.message, "position": e.position})
    where = f"investigation_id=? AND ({sql})" + (" AND alert_rank>0" if only else "")
    return where, [inv] + params


@app.get("/api/investigations/{inv}/events")
def events(inv: int, q: str = "", only: bool = False, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200), sort: str = "ts", dir: str = "asc"):
    con = conn()
    need(con, inv)
    where, params = _where(inv, q, only)
    col = sort if sort in SORTABLE else "ts"
    d = "DESC" if dir == "desc" else "ASC"
    total = con.execute(f"SELECT COUNT(*) n FROM events WHERE {where}", params).fetchone()["n"]
    rows = con.execute(f"SELECT {EV_COLS} FROM events WHERE {where} ORDER BY {col} {d}, id LIMIT ? OFFSET ?", params + [size, (page - 1) * size]).fetchall()
    return {"total": total, "page": page, "size": size, "rows": [dict(r) for r in rows]}


def safe_cell(v):
    """Evita inyección de fórmulas al abrir el CSV en Excel."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") and s != "-" else s


@app.get("/api/investigations/{inv}/events/export.csv")
def export(inv: int, q: str = "", only: bool = True):
    con = conn()
    need(con, inv)
    where, params = _where(inv, q, only)
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["log_id", "ts", "alert_severity", "event_id", "host", "user", "src_ip", "dest", "log_source", "description", "cmd", "result", "severity_src"]
    w.writerow(["Log_ID", "Fecha_Hora", "Alerta", "Event_ID", "Equipo", "Usuario", "IP_Origen", "Destino", "Fuente", "Descripcion", "Process_CommandLine", "Resultado", "Severidad_Original"])
    for r in con.execute(f"SELECT {','.join(cols)} FROM events WHERE {where} ORDER BY ts,id", params):
        w.writerow([safe_cell(r[c]) for c in cols])
    return StreamingResponse(iter(["﻿" + buf.getvalue()]), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="eventos_peligrosos.csv"'})


class ReportReq(BaseModel):
    min_severity: str = Field("Alto", pattern="^(Crítico|Alto|Medio|Bajo)$")
    sections: list[str] | None = None
    analyst: str = Field("", max_length=120)
    organization: str = Field("", max_length=120)


@app.get("/api/investigations/{inv}/report/preview")
def report_preview(inv: int, min_severity: str = "Alto"):
    con = conn()
    need(con, inv)
    return report.scope(con, inv, min_severity)


@app.post("/api/investigations/{inv}/report")
def make_report(inv: int, req: ReportReq):
    con = conn()
    need(con, inv)
    pdf = report.build(con, inv, req.min_severity, req.sections, req.analyst.strip(), req.organization.strip())
    base = re.sub(r"[^\w.-]+", "_", con.execute("SELECT name FROM investigations WHERE id=?", (inv,)).fetchone()["name"]).strip("_")[:60]
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote('Informe_' + re.sub(r"\.(xlsx|xlsm|csv|tsv|txt|json|ndjson|jsonl)$", "", base, flags=re.I) + '.pdf')}"})


if STATIC.exists():
    app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")


@app.get("/{path:path}", include_in_schema=False)
def spa(path: str):
    if path.startswith("api/"):
        raise HTTPException(404)
    index = STATIC / "index.html"
    if not index.exists():
        return JSONResponse({"detail": "Falta compilar la interfaz."}, status_code=503)
    return FileResponse(index)
