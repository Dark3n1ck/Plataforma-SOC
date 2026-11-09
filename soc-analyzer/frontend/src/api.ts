export type Sev = "Crítico" | "Alto" | "Medio" | "Bajo";
export interface Inv { id: number; name: string; created_at: string; ts_min: string; ts_max: string; total_events: number; findings: number }
export interface Ev { id: number; source?: string; log_id: string | null; ts: string; host: string | null; event_id: string | null; user: string | null; src_ip: string | null; dest: string | null; log_source?: string | null; description: string | null; cmd: string | null; result: string | null; severity_src?: string | null; alert_severity?: Sev | null; alert_rank?: number }
export interface Mitre { id: string; name: string; tactic: string }
export interface Finding { id: number; code: string; rule_id: string; title: string; severity: Sev; rank: number; description: string; why: string[]; fix: string[]; mitre: Mitre[]; ts_start: string; ts_end: string; src_ips: string[]; users: string[]; hosts: string[]; primary_user: string | null; target: string | null; incident: string | null; events: Ev[] }
export interface Link { from: string; to: string; reason: string; state: string }
export interface Incident { id: number; code: string; title: string; severity: Sev; ts_start: string; ts_end: string; hosts: string[]; users: string[]; src_ips: string[]; links: Link[]; analysis: { hypothesis: string; alternative: string; pending: string }; findings: Finding[]; context: Ev[] }
export interface Relation { a: string; b: string; kind: string; detail: string; state: string }
export interface Preview { filename: string; sha256: string; rows: number; columns: string[]; mapping: Record<string, string | null>; sample: Record<string, string>; duplicate: { id: number; name: string } | null }
export interface Dash {
  investigation: { id: number; name: string; ts_min: string; ts_max: string; total_events: number; quality: any; coverage: { total: number; evaluable: number; rules: { id: string; name: string; evaluable: boolean }[] }; files: { filename: string; sha256: string }[] };
  kpis: Record<string, number>;
  timeline: { t: string; normal: number; hot: number }[];
  tactics: { tactic: string; count: number }[];
  tops: Record<string, { k: string; v: number }[]>;
  source_severity: { k: string; v: number }[];
  incidents: { code: string; title: string; severity: Sev; ts_start: string; ts_end: string; hosts: string[]; alerts: number }[];
}
export class ApiError extends Error { position?: number; constructor(m: string, p?: number) { super(m); this.position = p; } }
export async function api<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init);
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    const d = j.detail;
    throw new ApiError(typeof d === "string" ? d : d?.message ?? "Ocurrió un error en el servidor.", d?.position);
  }
  return r.json();
}
export async function download(url: string, init: RequestInit | undefined, fallback: string) {
  const r = await fetch(url, init);
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new ApiError(typeof j.detail === "string" ? j.detail : j.detail?.message ?? "No se pudo descargar."); }
  const star = /filename\*=UTF-8''([^;]+)/.exec(r.headers.get("content-disposition") ?? "");
  const plain = /filename="([^"]+)"/.exec(r.headers.get("content-disposition") ?? "");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(await r.blob());
  a.download = star ? decodeURIComponent(star[1]) : plain?.[1] ?? fallback;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
