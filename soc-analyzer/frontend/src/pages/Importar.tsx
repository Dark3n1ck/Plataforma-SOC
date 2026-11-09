import { useState } from "react";
import { api, Preview } from "../api";
interface Meta { fields: { id: string; label: string; required: boolean }[] }
import { useData } from "./common";

export default function Importar({ active, activeName, onDone }: { active: number | null; activeName?: string; onDone: (id: number) => void }) {
  const { data: meta } = useData<Meta>("/api/meta");
  const [file, setFile] = useState<File | null>(null); const [p, setP] = useState<Preview | null>(null); const [map, setMap] = useState<Record<string, string | null>>({});
  const [name, setName] = useState(""); const [add, setAdd] = useState(false); const [busy, setBusy] = useState(false); const [err, setErr] = useState(""); const [over, setOver] = useState(false);
  const pick = async (f?: File) => {
    if (!f) return; setErr(""); setP(null); setFile(f); setBusy(true);
    try { const fd = new FormData(); fd.append("file", f); const r = await api<Preview>("/api/imports/preview", { method: "POST", body: fd }); setP(r); setMap(r.mapping); setName(f.name); }
    catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  const analyze = async () => {
    if (!file) return; setBusy(true); setErr("");
    try { const fd = new FormData(); fd.append("file", file); fd.append("mapping", JSON.stringify(map)); fd.append("name", name); if (add && active) fd.append("add_to", String(active)); const r = await api<{ id: number }>("/api/investigations", { method: "POST", body: fd }); onDone(r.id); }
    catch (e: any) { setErr(e.message); setBusy(false); }
  };
  const missing = meta?.fields.filter(f => !map[f.id]) ?? [];
  const cols = "190px 220px minmax(170px,1fr) 80px";
  return <main>
    <div><h1>Nueva investigación</h1><p className="sub">Cada importación se analiza y se informa por separado. Para correlacionar varios archivos, agrégalos a la misma investigación.</p></div>
    <label className={`drop ${over ? "over" : ""}`} onDragOver={e => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={e => { e.preventDefault(); setOver(false); pick(e.dataTransfer.files[0]); }}>
      <b style={{ fontSize: 15 }}>Arrastra un archivo o selecciónalo</b><span className="muted">CSV, XLSX o JSON, hasta 200 MB</span>
      <input type="file" accept=".csv,.tsv,.txt,.xlsx,.xlsm,.json,.ndjson,.jsonl" onChange={e => pick(e.target.files?.[0])} />
    </label>
    {err && <div className="error" role="alert">{err}</div>}
    {busy && !p && <div className="muted">Leyendo el archivo…</div>}
    {p && <div className="row">
      <section className="card f2"><h2>Mapeo de columnas</h2><p className="muted" style={{ margin: "4px 0 12px" }}>El sistema propone cada columna y tú la confirmas antes de analizar.</p>
        <div className="scroll"><div style={{ minWidth: 670 }}><div className="grid th" style={{ gridTemplateColumns: cols, padding: 0 }}><span>Dato de la plataforma</span><span>Columna del archivo</span><span>Ejemplo</span><span>Estado</span></div>
          {meta?.fields.map(f => <div className="grid" key={f.id} style={{ gridTemplateColumns: cols, padding: "6px 0" }}><span>{f.label}{f.required ? " *" : ""}</span>
            <select aria-label={f.label} value={map[f.id] ?? ""} onChange={e => setMap({ ...map, [f.id]: e.target.value || null })}><option value="">Sin columna</option>{p.columns.map(c => <option key={c}>{c}</option>)}</select>
            <span className="mono muted" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{map[f.id] ? p.sample[map[f.id]!] : "—"}</span><span className={map[f.id] ? "ok small" : "c-Medio small"}>{map[f.id] ? "Mapeada" : "Falta"}</span></div>)}
        </div></div></section>
      <div className="list f1">
        <section className="card"><h2 style={{ marginBottom: 10 }}>Archivo</h2><span className="lab">Nombre</span><div style={{ margin: "2px 0 10px", overflowWrap: "anywhere" }}>{p.filename}</div><span className="lab">SHA-256</span><div className="mono" style={{ margin: "2px 0 10px", overflowWrap: "anywhere", fontSize: 12 }}>{p.sha256}</div><span className="lab">Registros detectados</span><div>{p.rows}</div></section>
        {missing.length > 0 && <section className="warn"><h2>Columnas sin asignar</h2><p style={{ margin: "6px 0 0", fontSize: 13 }}>Algunas reglas no podrán evaluarse: {missing.map(m => m.label).join(", ")}.</p></section>}
        {p.duplicate && <section className="warn"><h2>Este archivo ya se importó</h2><p style={{ margin: "6px 0 10px", fontSize: 13 }}>Coincide con «{p.duplicate.name}». Puedes abrir esa investigación o crear otra.</p><button className="btn" onClick={() => onDone(p.duplicate!.id)}>Abrir la investigación anterior</button></section>}
        <section className="card"><label className="field">Nombre de la investigación<input type="text" value={name} onChange={e => setName(e.target.value)} maxLength={200} disabled={add} /></label>
          {active && <label className="check"><input type="checkbox" checked={add} onChange={e => setAdd(e.target.checked)} />Agregar a «{activeName}»</label>}</section>
        <button className="btn pri" disabled={busy || !map.ts} onClick={analyze}>{busy ? "Analizando…" : p.duplicate ? "Crear otra investigación" : "Analizar y crear investigación"}</button>
      </div></div>}
  </main>;
}
