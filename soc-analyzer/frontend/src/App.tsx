import { useCallback, useEffect, useState } from "react";
import { api, Inv } from "./api";
import Importar from "./pages/Importar";
import Dashboard from "./pages/Dashboard";
import Hallazgos from "./pages/Hallazgos";
import Explorador from "./pages/Explorador";
import Correlacion from "./pages/Correlacion";
import MitrePage from "./pages/Mitre";
import Informe from "./pages/Informe";

const NAV: [string, string][] = [["importar", "Importar"], ["dashboard", "Dashboard"], ["hallazgos", "Hallazgos"], ["explorador", "Explorador de eventos"], ["correlacion", "Correlación"], ["mitre", "MITRE ATT&CK"], ["informe", "Informe"]];
const read = () => { try { return Number(localStorage.getItem("inv")) || null; } catch { return null; } };

export default function App() {
  const [route, setRoute] = useState(location.hash.slice(2) || "dashboard");
  const [invs, setInvs] = useState<Inv[] | null>(null);
  const [active, setActive] = useState<number | null>(read());
  const page = route.split("?")[0];

  useEffect(() => { const f = () => setRoute(location.hash.slice(2) || "dashboard"); addEventListener("hashchange", f); return () => removeEventListener("hashchange", f); }, []);
  const refresh = useCallback(async () => {
    const l = await api<Inv[]>("/api/investigations"); setInvs(l);
    setActive(a => (a && l.some(i => i.id === a) ? a : l[0]?.id ?? null));
  }, []);
  useEffect(() => { refresh().catch(() => setInvs([])); }, [refresh]);
  useEffect(() => { try { if (active) localStorage.setItem("inv", String(active)); } catch { /* opcional */ } }, [active]);

  const open = (id: number) => { setActive(id); refresh(); location.hash = "#/dashboard"; };
  const remove = async () => {
    if (!active || !confirm("¿Eliminar esta investigación y todos sus eventos?")) return;
    await api(`/api/investigations/${active}`, { method: "DELETE" }); setActive(null); refresh();
  };

  let body;
  if (page === "importar") body = <Importar active={active} activeName={invs?.find(i => i.id === active)?.name} onDone={open} />;
  else if (invs === null) body = <div className="empty">Cargando…</div>;
  else if (!active) body = <div className="empty"><p>Todavía no hay investigaciones.</p><a className="btn pri" href="#/importar">Importar un archivo</a></div>;
  else if (page === "hallazgos") body = <Hallazgos key={active} inv={active} />;
  else if (page === "explorador") body = <Explorador key={active} inv={active} initial={decodeURIComponent(route.split("?q=")[1] ?? "")} />;
  else if (page === "correlacion") body = <Correlacion key={active} inv={active} />;
  else if (page === "mitre") body = <MitrePage key={active} inv={active} />;
  else if (page === "informe") body = <Informe key={active} inv={active} />;
  else body = <Dashboard key={active} inv={active} />;

  return <div className="shell">
    <aside className="side">
      <div className="brand"><b>Plataforma SOC</b><span>Análisis de eventos</span></div>
      <nav className="nav" aria-label="Principal">{NAV.map(([k, l]) => <a key={k} href={`#/${k}`} className={page === k ? "on" : ""}>{l}</a>)}</nav>
      <p className="note">Procesamiento local. Los comandos de los registros se muestran como texto y nunca se ejecutan.</p>
    </aside>
    <div className="content">
      <header className="top">
        <label className="field grow">Investigación activa
          <select value={active ?? ""} onChange={e => setActive(Number(e.target.value))} disabled={!invs?.length}>
            {!invs?.length && <option value="">Sin investigaciones</option>}
            {invs?.map(i => <option key={i.id} value={i.id}>{i.name} · {i.total_events} eventos</option>)}
          </select>
        </label>
        {active && <button className="btn" onClick={remove}>Eliminar</button>}
        <a className="btn" href="#/importar">Importar</a>
        <a className="btn pri" href="#/informe">Generar informe</a>
      </header>
      {body}
    </div>
  </div>;
}
