"""Inicia la plataforma en este equipo: python run.py"""
import sys
import threading
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))
import uvicorn  # noqa: E402

URL = "http://127.0.0.1:8080"
if __name__ == "__main__":
    if "--no-browser" not in sys.argv:
        threading.Timer(1.5, lambda: webbrowser.open(URL)).start()
    print(f"Plataforma SOC disponible en {URL} (Ctrl+C para detener)")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8080, log_level="warning")
