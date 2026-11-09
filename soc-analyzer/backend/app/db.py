"""Persistencia en SQLite. Todo cuelga de investigation_id para aislar cada importación."""
import os
import sqlite3
from pathlib import Path

DB_PATH = Path(os.environ.get("SOC_DB", Path(__file__).resolve().parents[2] / "data" / "soc.db"))

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS investigations(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, created_at TEXT NOT NULL,
  ts_min TEXT, ts_max TEXT, total_events INTEGER DEFAULT 0, quality TEXT DEFAULT '{}', coverage TEXT DEFAULT '{}');
CREATE TABLE IF NOT EXISTS files(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  filename TEXT NOT NULL, sha256 TEXT NOT NULL, imported_at TEXT NOT NULL, row_count INTEGER, mapping TEXT);
CREATE INDEX IF NOT EXISTS ix_files_sha ON files(sha256);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  source TEXT NOT NULL DEFAULT 'import', row_hash TEXT NOT NULL, log_id TEXT, ts TEXT NOT NULL, host TEXT, host_raw TEXT,
  event_id TEXT, user TEXT, src_ip TEXT, dest TEXT, log_source TEXT, description TEXT, cmd TEXT, result TEXT,
  severity_src TEXT, alert_severity TEXT, alert_rank INTEGER DEFAULT 0, raw TEXT,
  UNIQUE(investigation_id,row_hash));
CREATE INDEX IF NOT EXISTS ix_ev_inv_ts ON events(investigation_id,ts);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  code TEXT NOT NULL, rule_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, rank INTEGER NOT NULL,
  description TEXT, why TEXT, fix TEXT, mitre TEXT, ts_start TEXT, ts_end TEXT, src_ips TEXT, users TEXT, hosts TEXT,
  primary_user TEXT, target TEXT, incident_id INTEGER);
CREATE INDEX IF NOT EXISTS ix_f_inv ON findings(investigation_id);
CREATE TABLE IF NOT EXISTS finding_events(
  finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  event_pk INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE, PRIMARY KEY(finding_id,event_pk));
CREATE INDEX IF NOT EXISTS ix_fe_ev ON finding_events(event_pk);
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  code TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, rank INTEGER NOT NULL, ts_start TEXT, ts_end TEXT,
  hosts TEXT, users TEXT, src_ips TEXT, narrative TEXT, links TEXT, analysis TEXT);
CREATE TABLE IF NOT EXISTS relations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  a TEXT, b TEXT, kind TEXT, detail TEXT, state TEXT);
"""


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init() -> None:
    con = connect()
    con.executescript(SCHEMA)
    con.commit()
    con.close()
