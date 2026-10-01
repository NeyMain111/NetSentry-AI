from __future__ import annotations

import asyncio
import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .advisor import SecurityAdvisor
from .capture import CaptureController, PacketProcessor
from .detector import ThreatDetector
from .models import AdvisorRequest, AdvisorResponse, AdvisorStatus, StartCaptureRequest
from .store import TrafficStore


BASE_DIR = Path(__file__).resolve().parent
store = TrafficStore()
detector = ThreatDetector()
processor = PacketProcessor(store, detector)
capture = CaptureController(processor)
advisor = SecurityAdvisor(store, capture.status)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if os.getenv("NETSENTRY_AUTO_DEMO") == "1":
        capture.start("demo")
    yield
    if capture.running:
        capture.stop()


app = FastAPI(
    title="NetSentry AI",
    version="0.2.0",
    description="Local packet metadata monitor and explainable anomaly detector",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(BASE_DIR / "templates" / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": "0.2.0"}


@app.get("/api/interfaces")
def interfaces() -> dict:
    return {"interfaces": capture.interfaces()}


@app.get("/api/status")
def status() -> dict:
    return capture.status()


@app.get("/api/snapshot")
def snapshot(
    limit: int = Query(250, ge=1, le=1000),
    protocol: str | None = None,
    suspicious: bool | None = None,
    q: str | None = Query(None, max_length=100),
) -> dict:
    result = store.snapshot(limit=limit, protocol=protocol, suspicious=suspicious, query=q)
    result["capture"] = capture.status()
    return result


@app.post("/api/capture/start")
def start_capture(request: StartCaptureRequest) -> dict:
    try:
        capture.start(request.mode, request.interface)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return capture.status()


@app.post("/api/capture/stop")
def stop_capture() -> dict:
    capture.stop()
    return capture.status()


@app.delete("/api/data")
def clear_data() -> dict:
    store.clear()
    detector.reset()
    return {"status": "cleared"}


@app.get("/api/export.csv", response_class=PlainTextResponse)
def export_csv() -> PlainTextResponse:
    return PlainTextResponse(
        store.to_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=netsentry-capture.csv"},
    )


@app.post("/api/import/pcap")
async def import_pcap(file: UploadFile = File(...)) -> dict:
    suffix = Path(file.filename or "capture.pcap").suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(status_code=400, detail="Upload a .pcap, .pcapng, or .cap file.")

    total = 0
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temporary:
            temporary_path = Path(temporary.name)
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > 100 * 1024 * 1024:
                    raise HTTPException(status_code=413, detail="PCAP files are limited to 100 MB.")
                temporary.write(chunk)
        processed = await asyncio.to_thread(capture.import_pcap, temporary_path)
        return {"status": "imported", "packets": processed}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not read PCAP: {exc}") from exc
    finally:
        await file.close()
        if temporary_path and temporary_path.exists():
            temporary_path.unlink(missing_ok=True)


@app.post("/api/advisor", response_model=AdvisorResponse)
async def ask_advisor(request: AdvisorRequest) -> AdvisorResponse:
    alert = store.get_alert(request.alert_id) if request.alert_id else None
    if request.alert_id and alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return await advisor.answer(request.question, alert, request.history)


@app.get("/api/advisor/status", response_model=AdvisorStatus)
async def advisor_status() -> AdvisorStatus:
    return await advisor.status()
