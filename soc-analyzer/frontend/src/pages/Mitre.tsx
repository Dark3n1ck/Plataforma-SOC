import { Sev } from "../api";
import { Badge, Loading, useData } from "./common";
interface T { id: string; name: string; count: number; severity: Sev; findings: string[] }
export default function MitrePage({ inv }: { inv: number }) {
  const { data, error } = useData<{ tactic: string; count: number; techniques: T[] }[]>(`/api/investigations/${inv}/mitre`);
  if (!data) return <Loading error={error} />;
  return <main>
    <div><h1>MITRE ATT&amp;CK</h1><p className="sub">Solo aparecen las técnicas observadas en esta investigación.</p></div>
    <section className="mitre">{data.map(t => <div className="card" style={{ padding: 14 }} key={t.tactic}><div className="sp"><h2 style={{ fontSize: 14 }}>{t.tactic}</h2><span className="muted small">{t.count}</span></div>
      {t.techniques.map(x => <a className="tech" href="#/hallazgos" key={x.id}><span className="sp"><span className="mono small">{x.id}</span><Badge s={x.severity} /></span><span className="n">{x.name}</span><span className="small muted">{x.findings.join(", ")}</span></a>)}</div>)}</section>
  </main>;
}
