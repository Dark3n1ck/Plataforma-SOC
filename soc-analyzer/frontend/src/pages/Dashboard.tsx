import { Dash } from "../api";
import { Badge, day, hm, Loading, useData } from "./common";

export default function Dashboard({ inv }: { inv: number }) {
  const { data: d, error } = useData<Dash>(`/api/investigations/${inv}/dashboard`);
  if (!d) return <Loading error={error} />;
  const k = d.kpis, i = d.investigation, total = k.findings || 1;
  const deg = (n: number) => (n / total) * 360;
  let a = 0; const stops = ([["#F2545B", k.critical], ["#F59A3C", k.high], ["#EFCB4F", k.medium], ["#5AA9E6", k.low]] as [string, number][]).map(([c, n]) => { const s = `${c} ${a}deg ${a + deg(n)}deg`; a += deg(n); return s; }).join(",");
  const max = Math.max(1, ...d.timeline.map(b => b.normal + b.hot)), scale = 175 / max;
  const tmax = Math.max(1, ...d.tactics.map(t => t.count));
  const kpis: [string, number | string, string, string, string][] = [
    ["Eventos", k.events, `${k.sources} fuentes de log`, "", "explorador"], ["Hallazgos", k.findings, `${k.in_finding} eventos de evidencia`, "", "hallazgos"],
    ["Críticos", k.critical, "validación inmediata", "c-Crítico", "hallazgos"], ["Altos", k.high, "validación urgente", "c-Alto", "hallazgos"], ["Medios", k.medium, "revisar en el turno", "c-Medio", "hallazgos"], ["Bajos", k.low, "seguimiento", "c-Bajo", "hallazgos"],
    ["Incidentes", k.incidents, "hallazgos correlacionados", "", "correlacion"], ["Equipos", k.hosts_hot, `de ${k.hosts} con hallazgos`, "", "hallazgos"], ["Usuarios", k.users_hot, `de ${k.users} con hallazgos`, "", "hallazgos"],
  ];
  const tops: [string, string][] = [["src_ip", "IP de origen en hallazgos"], ["event_id", "Event ID más frecuentes"], ["host", "Equipos en hallazgos"], ["user", "Usuarios en hallazgos"]];
  const cols = "90px 80px minmax(280px,1fr) 170px 130px 60px";
  return <main>
    <div><h1>Resumen de la investigación</h1><p className="sub">{i.total_events} eventos · {day(i.ts_min)}, {hm(i.ts_min).slice(0, 5)} a {hm(i.ts_max).slice(0, 5)} · Todo lo que ves pertenece solo a esta investigación.</p></div>
    <section className="kpis">{kpis.map(([l, v, s, c, h]) => <a className="kpi" href={`#/${h}`} key={l}><small>{l}</small><b className={c}>{v}</b><span>{s}</span></a>)}</section>
    <div className="row stretch">
      <section className="card f2">
        <div className="head"><h2>Eventos cada 30 minutos</h2><div className="legend"><span><i className="sw norm" />Normal</span><span><i className="sw hot" />En hallazgo</span></div></div>
        <div className="chart">{d.timeline.map(b => <div className="bar" key={b.t} title={`${b.t.slice(11)} · ${b.normal + b.hot} eventos, ${b.hot} en hallazgo`}><i className="hot" style={{ height: b.hot * scale }} /><i className="norm" style={{ height: b.normal * scale }} /></div>)}</div>
        <div className="axis">{d.timeline.map((b, n) => <span key={b.t}>{n % 2 ? "" : b.t.slice(11)}</span>)}</div>
      </section>
      <section className="card f1">
        <h2>Hallazgos por severidad</h2>
        <div className="donutw">
          <div className="donut" style={{ background: `conic-gradient(${stops})` }} role="img" aria-label={`${k.critical} críticos, ${k.high} altos, ${k.medium} medios y ${k.low} bajos`}><div><b>{k.findings}</b><span>hallazgos</span></div></div>
          <div className="leg">{([["Crítico", "#F2545B", k.critical], ["Alto", "#F59A3C", k.high], ["Medio", "#EFCB4F", k.medium], ["Bajo", "#5AA9E6", k.low]] as [string, string, number][]).map(([l, c, n]) => <div key={l}><i className="sw" style={{ background: c }} /><em>{l}</em><span>{n}</span></div>)}</div>
        </div>
      </section>
    </div>
    <div className="row stretch">
      <section className="card f1"><h2>Hallazgos por táctica MITRE</h2>{d.tactics.map(t => <div className="hbar" key={t.tactic}><span>{t.tactic}</span><span className="track"><i style={{ width: `${(t.count / tmax) * 100}%` }} /></span><b>{t.count}</b></div>)}</section>
      <section className="card f1"><h2 style={{ marginBottom: 14 }}>Lo más activo</h2><div className="tops">{tops.map(([key, title]) => <div key={key}><h3>{title}</h3>{d.tops[key].slice(0, 5).map(r => <div className="tr" key={r.k}><span>{r.k}</span><span>{r.v}</span></div>)}</div>)}</div></section>
    </div>
    <section className="card"><h2 style={{ marginBottom: 12 }}>Incidentes correlacionados</h2><div className="scroll"><div style={{ minWidth: 780 }}>
      <div className="grid th" style={{ gridTemplateColumns: cols }}><span>Severidad</span><span>ID</span><span>Incidente</span><span>Equipos</span><span>Inicio</span><span>Alertas</span></div>
      {d.incidents.map(x => <a className="grid" href="#/correlacion" key={x.code} style={{ gridTemplateColumns: cols }}><span><Badge s={x.severity} /></span><span className="mono">{x.code}</span><span>{x.title}</span><span className="mono">{x.hosts.join(", ")}</span><span className="small">{day(x.ts_start)} {x.ts_start.slice(11, 16)}</span><span>{x.alerts}</span></a>)}
    </div></div></section>
    <section className="card row">
      <div className="f1"><h2>Cobertura de reglas</h2><div style={{ font: "600 26px var(--head)", marginTop: 6 }}>{i.coverage.evaluable} de {i.coverage.total}</div><div className="track" style={{ marginTop: 8 }}><i style={{ width: `${(i.coverage.evaluable / i.coverage.total) * 100}%` }} /></div></div>
      <p className="f2 muted" style={{ margin: 0 }}>{i.coverage.evaluable < i.coverage.total ? `No se evaluaron por falta de ese tipo de evento: ${i.coverage.rules.filter(r => !r.evaluable).map(r => r.name).join(", ")}. Cero hallazgos en esas reglas no significa que no exista esa actividad.` : "Todas las reglas pudieron evaluarse con este archivo."}</p>
    </section>
  </main>;
}
