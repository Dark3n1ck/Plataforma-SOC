# Plataforma SOC

Sistema local para importar logs, detectar y clasificar eventos peligrosos, correlacionarlos y generar un informe profesional en PDF.

## Cómo iniciarlo

Requiere Python 3.10 o superior.

- **Windows:** doble clic en `iniciar.bat`.
- **Linux o macOS:** ejecuta `./iniciar.sh`.

La primera vez instala las dependencias. Después abre `http://127.0.0.1:8000`.

La interfaz ya viene compilada, así que no necesitas Node.js. Solo hace falta para modificarla: `cd frontend && npm install && npm run build`.

## Uso

1. **Importar:** carga un CSV, XLSX o JSON y confirma el mapeo de columnas.
2. **Dashboard:** revisa eventos, severidades, MITRE, incidentes y cobertura de reglas.
3. **Hallazgos:** consulta IP de origen, fecha y hora, descripción, `Process_CommandLine`, ID del evento, objetivo, usuario, motivo de la severidad y solución.
4. **Explorador:** busca con el lenguaje de consultas y exporta solo los eventos peligrosos.
5. **Correlación:** revisa la cadena de cada incidente y su relación con otros.
6. **Informe:** elige la severidad mínima y las secciones, y genera el PDF.

Cada importación crea una investigación independiente. El dashboard, las búsquedas, la correlación y el informe usan solo los datos de la investigación activa.

## Lenguaje de búsqueda

| Elemento | Sintaxis |
|---|---|
| Lógica | `AND`, `OR`, `NOT`, paréntesis. Dos términos seguidos equivalen a `AND` |
| Comparación | `:` `=` `!=` `>` `>=` `<` `<=` |
| Comodines | `*` y `?` |
| Texto libre | `vssadmin` o `"delete shadows"` |

**Campos:** `ts`, `host`, `event_id`, `user`, `src_ip`, `dest`, `log_source`, `description`, `cmd`, `result`, `severity`, `alert`, `log_id`, `source`.

También acepta nombres de Wazuh, como `agent.name`, `data.srcip`, `rule.description` y `data.win.eventdata.commandLine`.

```text
event_id:4625 AND NOT src_ip:10.*
user:admin AND (event_id:4688 OR event_id:4104)
alert >= alto AND cmd:*powershell*
ts >= "2026-10-23 09:00" AND ts < "2026-10-23 10:00"
```

La consulta se compila a SQL parametrizado con una lista cerrada de campos.

## Estructura

```text
backend/app/ingest.py     lectura, mapeo y normalización
backend/app/rules.py      24 reglas de detección con MITRE ATT&CK
backend/app/correlate.py  incidentes y relaciones
backend/app/query.py      lenguaje de búsqueda
backend/app/report.py     informe PDF
backend/app/main.py       API
frontend/src/             interfaz React
backend/tests/            pruebas (python -m pytest backend/tests)
```

## Seguridad implementada

- Solo escucha en `127.0.0.1` y valida los encabezados `Host` y `Origin`.
- Limita tamaño, tipo y filas de los archivos, y protege la lectura de XLSX contra bombas ZIP.
- Usa SQL parametrizado, cabeceras CSP y escape de los datos en la interfaz y el PDF.
- Neutraliza fórmulas al exportar a CSV.
- Nunca ejecuta los comandos de los registros, y los datos no salen del equipo.

**Pendiente antes de publicarlo en una red:** autenticación con MFA, roles, TLS, registro de auditoría y cifrado de la base de datos. Esta versión no tiene inicio de sesión.

