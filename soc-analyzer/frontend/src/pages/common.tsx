import { useEffect, useState } from "react";
import { api, Sev } from "../api";
export const Badge = ({ s }: { s?: Sev | null }) => <span className={`badge sev-${s ?? "none"}`}>{s ?? "Normal"}</span>;
export const hm = (ts: string) => ts.slice(11);
const M = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"];
export const day = (ts: string) => `${+ts.slice(8, 10)}-${M[+ts.slice(5, 7) - 1]}-${ts.slice(0, 4)}`;
export function useData<T>(url: string) {
  const [data, setData] = useState<T | null>(null); const [error, setError] = useState("");
  useEffect(() => { let on = true; setData(null); api<T>(url).then(d => on && setData(d)).catch(e => on && setError(e.message)); return () => { on = false; }; }, [url]);
  return { data, error };
}
export const Loading = ({ error }: { error?: string }) => <div className="empty">{error || "Cargando…"}</div>;
