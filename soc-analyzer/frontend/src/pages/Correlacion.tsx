import { Fragment, useState } from "react";
import { Incident, Relation } from "../api";
import { Badge, day, hm, Loading, useData } from "./common";

export default function Correlacion({ inv }: { inv: number }) {
  const { data, error } = useData<{ incidents: Incident[]; relations: Relation[] }>(`/api/investigations/${inv}/incidents`);
  const [sel, setSel] = useState<number | null>(null);
  if (!data) return <Loading error={error} />;
  const i = data.incidents.find(x => x.id === sel) ?? data.incidents[0];
  if (!i) return <main><h1>Correlación</h1><div className="empty">No se formaron incidentes en esta investigación.</div></main>;
  const rel = data.relations.filter(r => r.a === i.code || r.b === i.code);
  return <main>
    <div><h1>Correlación</h1><p className="sub">Cada enlace indica qué dato une a los eventos y si la relación está confirmada.</p></div>
    <div className="row">
      <section className="list" style={{ flex: "1 1 250px", minWidth: 0 }} aria-label="Incidentes">{data.incidents.map(x => <button key={x.id} className={`item ${x.id === i.id ? "on" : ""}`} onClick={() => setSel(x.id)}><span className="sp"><Badge s={x.severity} /><span className="mono small muted">{x.code}</span></span><span className="t">{x.title}</span></button>)}</section>
      <section className="card f2 chain">
        <span className="mono muted">{i.code} · {day(i.ts_start)}, {hm(i.ts_start)} a {hm(i.ts_end)}</span>
        <h2 className="title2" style={{ margin: "6px 0 18px" }}>{i.title}</h2>
        {i.findings.map((f, n) => <Fragment key={f.id}>
          <div className="step"><time>{hm(f.ts_start)}</time><div style={{ minWidth: 0 }}>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}><span className="mono">{[...new Set(f.events.map(e => e.event_id))].join(", ")}{f.events.length > 1 ? ` × ${f.events.length}` : ""}</span><Badge s={f.severity} /></div>
            <div style={{ marginTop: 5, fontWeight: 500 }}>{f.title}</div><div style={{ marginTop: 3, color: "var(--tx2)" }}>{f.description}</div>
          </div></div>
          {i.links[n] && <div className={`lnk ${i.links[n].state}`}><span>{i.links[n].reason}</span><b>{i.links[n].state}</b></div>}
        </Fragment>)}
        {i.context.length > 0 && <p className="small muted" style={{ marginBottom: 0 }}>Eventos normales que dan contexto: {i.context.map(c => `${c.log_id} (${hm(c.ts)}, ${c.event_id})`).join("; ")}.</p>}
      </section>
      <div className="list" style={{ flex: "1 1 280px", minWidth: 0 }}>
        <section className="card"><h2>Análisis</h2><span className="lab" style={{ marginTop: 12 }}>Hipótesis principal</span><p style={{ margin: "4px 0 12px" }}>{i.analysis.hypothesis}</p><span className="lab">Hipótesis alternativa</span><p style={{ margin: "4px 0 12px" }}>{i.analysis.alternative}</p><span className="lab">Falta confirmar</span><p style={{ margin: "4px 0 0" }}>{i.analysis.pending}</p></section>
        <section className="card"><h2>Entidades</h2>{([["Origen", i.src_ips], ["Cuentas", i.users], ["Equipos", i.hosts]] as [string, string[]][]).map(([k, v]) => <div className="tr" key={k}><span style={{ color: "var(--mut)", fontFamily: "Inter" }}>{k}</span><span style={{ color: "var(--tx)", textAlign: "right" }}>{v.join(", ") || "—"}</span></div>)}</section>
        {rel.length > 0 && <section className="card"><h2>Relación con otros incidentes</h2>{rel.map((r, n) => <p key={n} className="small" style={{ margin: "10px 0 0" }}><b>{r.a === i.code ? r.b : r.a} · {r.kind}.</b> <span style={{ color: "var(--tx2)" }}>{r.detail}</span> <span className="c-Medio">{r.state}</span></p>)}</section>}
      </div>
    </div>
  </main>;
}
