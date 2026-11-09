import { useState } from "react";
import { download, Sev } from "../api";
import { Loading, useData } from "./common";

const SECTIONS: [string, string][] = [["summary", "Resumen ejecutivo"], ["scope", "Alcance y limitaciones"], ["incidents", "Detalle de incidentes"], ["timeline", "Cronología consolidada"], ["correlation", "Correlación entre incidentes"], ["mitre", "Técnicas MITRE ATT&CK"], ["dangerous", "Eventos más peligrosos"], ["actions", "Medidas recomendadas"], ["iocs", "Indicadores de compromiso"], ["evidence", "Anexo de evidencia"]];
const LV: Sev[] = ["Crítico", "Alto", "Medio", "Bajo"];
export default function Informe({ inv }: { inv: number }) {
  const [min, setMin] = useState<Sev>("Alto"); const [on, setOn] = useState(SECTIONS.map(s => s[0]));
  const [analyst, setAnalyst] = useState(""); const [org, setOrg] = useState(""); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const { data: s, error } = useData<Record<string, number>>(`/api/investigations/${inv}/report/preview?min_severity=${encodeURIComponent(min)}`);
  const gen = async () => { setBusy(true); setErr(""); try { await download(`/api/investigations/${inv}/report`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ min_severity: min, sections: on, analyst, organization: org }) }, "Informe_SOC.pdf"); } catch (e: any) { setErr(e.message); } finally { setBusy(false); } };
  return <main>
    <div><h1>Generar informe</h1><p className="sub">El informe contiene únicamente los eventos importados en esta investigación.</p></div>
    <div className="row">
      <div className="list f1">
        <section className="card"><h2 style={{ marginBottom: 10 }}>Datos del informe</h2><div className="list"><label className="field">Analista<input type="text" value={analyst} onChange={e => setAnalyst(e.target.value)} maxLength={120} /></label><label className="field">Organización<input type="text" value={org} onChange={e => setOrg(e.target.value)} maxLength={120} /></label></div></section>
        <section className="card"><h2 style={{ marginBottom: 10 }}>Severidad mínima</h2><div className="chips" role="group" aria-label="Severidad mínima">{LV.map(l => <button key={l} className={`chip ${l === min ? "on" : ""}`} aria-pressed={l === min} onClick={() => setMin(l)}>{l}</button>)}</div></section>
      </div>
      <div className="list f1">
        <section className="card"><h2 style={{ marginBottom: 6 }}>Secciones</h2>{SECTIONS.map(([k, l]) => <label className="check" key={k}><input type="checkbox" checked={on.includes(k)} onChange={() => setOn(on.includes(k) ? on.filter(x => x !== k) : [...on, k])} />{l}</label>)}</section>
      </div>
      <div className="list f1">
        <section className="card"><h2 style={{ marginBottom: 12 }}>Contenido del informe</h2>{!s ? <Loading error={error} /> : <div className="stat">{([["Incidentes", s.incidents], ["Hallazgos", s.findings], ["Eventos", s.events], ["Críticos", s.critical], ["Altos", s.high], ["Medios", s.medium]] as [string, number][]).map(([l, v]) => <div key={l}><span className="small muted">{l}</span><b>{v}</b></div>)}</div>}
          <p className="small muted" style={{ marginBottom: 0 }}>La severidad se aplica por incidente. Un incidente incluido conserva todos sus hallazgos para no romper la cadena del ataque.</p></section>
        <button className="btn pri" disabled={busy || on.length === 0} onClick={gen}>{busy ? "Generando…" : "Generar PDF"}</button>
        {err && <div className="error" role="alert">{err}</div>}
      </div>
    </div>
  </main>;
}
