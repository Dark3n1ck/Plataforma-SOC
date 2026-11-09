import { useMemo, useState } from "react";
import { Finding, Sev } from "../api";
import { Badge, hm, Loading, useData } from "./common";

const LEVELS: (Sev | "Todos")[] = ["Todos", "Crítico", "Alto", "Medio", "Bajo"];
export default function Hallazgos({ inv }: { inv: number }) {
  const { data, error } = useData<Finding[]>(`/api/investigations/${inv}/findings`);
  const [lv, setLv] = useState<(typeof LEVELS)[number]>("Todos");
  const [sel, setSel] = useState<number | null>(null);
  const list = useMemo(() => (data ?? []).filter(f => lv === "Todos" || f.severity === lv), [data, lv]);
  if (!data) return <Loading error={error} />;
  const f = list.find(x => x.id === sel) ?? list[0];
  const count = (l: string) => l === "Todos" ? data.length : data.filter(x => x.severity === l).length;
  const ev = f?.events.find(e => e.cmd && e.cmd !== "powershell.exe") ?? f?.events[0];
  return <main>
    <div><h1>Hallazgos</h1><p className="sub">Ordenados por severidad y hora.</p></div>
    <div className="chips" role="group" aria-label="Filtrar por severidad">{LEVELS.map(l => <button key={l} className={`chip ${l === lv ? "on" : ""}`} aria-pressed={l === lv} onClick={() => setLv(l)}>{l} · {count(l)}</button>)}</div>
    {!f ? <div className="empty">No hay hallazgos con esa severidad.</div> : <div className="row">
      <section className="list f1" aria-label="Lista de hallazgos">{list.map(x => <button className={`item ${x.id === f.id ? "on" : ""}`} key={x.id} onClick={() => setSel(x.id)}>
        <span className="sp"><Badge s={x.severity} /><span className="small muted">{x.incident ?? "Sin incidente"} · {hm(x.ts_start).slice(0, 5)}</span></span>
        <span className="t">{x.title}</span><span className="m">{x.src_ips.join(", ")} hacia {x.target}</span></button>)}</section>
      <article className="card f2">
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "center" }}><Badge s={f.severity} /><span className="mono muted">{f.code} · {f.mitre.map(m => m.id).join(", ")}</span></div>
        <h2 className="title2">{f.title}</h2>
        <div className="facts">
          <div><small>IP de origen</small><span>{f.src_ips.join(", ") || "—"}</span></div>
          <div><small>Fecha y hora</small><span>{f.ts_start === f.ts_end ? f.ts_start : `${f.ts_start} a ${hm(f.ts_end)}`}</span></div>
          <div><small>ID del evento</small><span>{[...new Set(f.events.map(e => e.event_id))].join(", ")}</span></div>
          <div><small>Objetivo del ataque</small><span>{f.target}</span></div>
          <div><small>Usuario</small><span>{f.primary_user ?? (f.users.length > 3 ? `${f.users.length} cuentas` : f.users.join(", ")) ?? "—"}</span></div>
          <div><small>Evidencia</small><span>{f.events.length} {f.events.length === 1 ? "evento" : "eventos"}</span></div>
        </div>
        <h3 className="lab" style={{ marginTop: 18, fontWeight: 500 }}>Descripción</h3><p style={{ margin: "4px 0 0" }}>{f.description}</p>
        <h3 className="lab" style={{ marginTop: 16, fontWeight: 500 }}>Process_CommandLine</h3><pre>{ev?.cmd || "El registro no incluye línea de comandos."}</pre>
        <div className="row" style={{ marginTop: 18, gap: 20 }}>
          <div className="f1"><h3>Por qué tiene esta severidad</h3><ul>{f.why.map(w => <li key={w}>{w}</li>)}</ul></div>
          <div className="f1"><h3>Cómo solucionarlo</h3><ol>{f.fix.map(w => <li key={w}>{w}</li>)}</ol></div>
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 20 }}>
          {f.incident && <a className="btn pri" href="#/correlacion">Ver correlación</a>}
          <a className="btn" href={`#/explorador?q=${encodeURIComponent(f.events.length <= 12 ? f.events.map(e => `log_id:"${e.log_id}"`).join(" OR ") : `log_id:"${f.events[0].log_id}"`)}`}>Ver eventos originales</a>
        </div>
      </article></div>}
  </main>;
}
