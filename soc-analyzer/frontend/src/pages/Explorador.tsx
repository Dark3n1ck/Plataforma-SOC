import { useCallback, useEffect, useState } from "react";
import { api, ApiError, download, Ev } from "../api";
import { Badge, Loading } from "./common";

const EXAMPLES = ['event_id:4625 AND result:Failure', 'NOT src_ip:10.* AND result:Success', 'user:admin AND (event_id:4688 OR event_id:4104)', 'alert >= alto AND cmd:*powershell*', 'host:FS-SRV01 AND dest:*Finance*', 'ts >= "2026-10-23 09:00" AND ts < "2026-10-23 10:00"'];
const FIELDS = "ts, host, event_id, user, src_ip, dest, log_source, description, cmd, result, severity, alert, log_id, source";
const COLS = "140px 76px 84px 112px 130px 130px minmax(180px,1fr) minmax(170px,1fr)";
interface Page { total: number; rows: Ev[] }

export default function Explorador({ inv, initial }: { inv: number; initial: string }) {
  const [text, setText] = useState(initial); const [q, setQ] = useState(initial);
  const [only, setOnly] = useState(false); const [page, setPage] = useState(1);
  const [data, setData] = useState<Page | null>(null); const [err, setErr] = useState(""); const [open, setOpen] = useState<number | null>(null);
  const size = 50;
  useEffect(() => { setText(initial); setQ(initial); setPage(1); }, [initial]);
  const url = useCallback((path: string, extra: Record<string, string>) => `/api/investigations/${inv}/${path}?${new URLSearchParams({ q, only: String(only), ...extra })}`, [inv, q, only]);
  useEffect(() => { let on = true; api<Page>(url("events", { page: String(page), size: String(size) })).then(d => { if (on) { setData(d); setErr(""); } }).catch((e: ApiError) => on && setErr(e.message)); return () => { on = false; }; }, [url, page]);
  const run = (v = text) => { setText(v); setQ(v); setPage(1); setOpen(null); };
  const pages = data ? Math.max(1, Math.ceil(data.total / size)) : 1;
  return <main>
    <div className="head" style={{ alignItems: "flex-end" }}>
      <div><h1>Explorador de eventos</h1><p className="sub">{data ? `${data.total} eventos encontrados` : "Buscando…"}</p></div>
      <button className="btn pri" onClick={() => download(url("events/export.csv", { only: "true" }), undefined, "eventos_peligrosos.csv").catch(e => setErr(e.message))}>Exportar eventos peligrosos</button>
    </div>
    <section className="card">
      <div className="row" style={{ alignItems: "flex-end" }}>
        <label className="field" style={{ flex: "0 1 220px" }}>Origen de los eventos
          <select defaultValue="import"><option value="import">Archivos importados</option><option value="wazuh" disabled>Wazuh (próxima fase)</option></select>
        </label>
        <form className="search grow" style={{ flex: "1 1 420px" }} onSubmit={e => { e.preventDefault(); run(); }}>
          <label className="field" style={{ flex: "1 1 320px" }}>Consulta
            <input type="search" className={err ? "err" : ""} value={text} onChange={e => setText(e.target.value)} placeholder='event_id:4625 AND NOT user:admin' spellCheck={false} aria-invalid={!!err} />
          </label>
          <button className="btn pri" style={{ alignSelf: "flex-end" }}>Buscar</button>
        </form>
        <label className="check"><input type="checkbox" checked={only} onChange={e => { setOnly(e.target.checked); setPage(1); }} />Solo eventos peligrosos</label>
      </div>
      {err && <div className="error" role="alert">{err}</div>}
      <details style={{ marginTop: 10 }}><summary>Cómo buscar</summary>
        <p className="muted small" style={{ margin: "6px 0" }}>Operadores: <span className="mono">AND OR NOT ( )</span> · Comparadores: <span className="mono">: = != &gt; &gt;= &lt; &lt;=</span> · Comodines: <span className="mono">* ?</span> · Texto libre: escribe una palabra o una frase entre comillas. También se aceptan nombres de Wazuh, como <span className="mono">agent.name</span> y <span className="mono">data.srcip</span>.</p>
        <p className="muted small" style={{ margin: "6px 0" }}>Campos: <span className="mono">{FIELDS}</span></p>
        <div className="chips">{EXAMPLES.map(x => <button type="button" className="ex" key={x} onClick={() => run(x)}>{x}</button>)}</div>
      </details>
    </section>
    {!data ? <Loading /> : <section className="card scroll" style={{ padding: 0 }}><div style={{ minWidth: 1140 }}>
      <div className="evrow th" style={{ gridTemplateColumns: COLS }}><span>Fecha y hora</span><span>Alerta</span><span>ID</span><span>IP de origen</span><span>Usuario</span><span>Objetivo</span><span>Process_CommandLine</span><span>Descripción</span></div>
      {data.rows.length === 0 && <div className="empty">Ninguna coincidencia con esta consulta.</div>}
      {data.rows.map(r => <div key={r.id}>
        <button className="evrow" style={{ gridTemplateColumns: COLS }} aria-expanded={open === r.id} onClick={() => setOpen(open === r.id ? null : r.id)}>
          <span className="m12">{r.ts}</span><span><Badge s={r.alert_severity} /></span><span className="m12">{r.event_id}</span><span className="m12">{r.src_ip}</span><span className="m12">{r.user}</span><span className="m12">{r.dest || r.host}</span><code className="m12">{r.cmd}</code><span style={{ color: "var(--tx2)" }}>{r.description}</span>
        </button>
        {open === r.id && <div className="exp"><div className="facts" style={{ marginTop: 0 }}>{([["Registro", r.log_id], ["Equipo", r.host], ["Destino", r.dest], ["Fuente", r.log_source], ["Resultado", r.result], ["Severidad original", r.severity_src]] as [string, string | null][]).map(([l, v]) => <div key={l}><small>{l}</small><span>{v || "—"}</span></div>)}</div></div>}
      </div>)}
      <div className="pager"><span className="muted small">Página {page} de {pages}</span><button className="btn" disabled={page <= 1} onClick={() => setPage(page - 1)}>Anterior</button><button className="btn" disabled={page >= pages} onClick={() => setPage(page + 1)}>Siguiente</button></div>
    </div></section>}
  </main>;
}
