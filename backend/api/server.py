import os
import asyncio
import time
import tempfile
from typing import List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from backend.schema.alert_schema import StandardizedAlert
from backend.ingest.flow_generator import FlowStreamGenerator
from backend.ingest.pcap_stream import PCAPStreamReader
from backend.pipeline.streaming_engine import StreamingPipelineEngine
from backend.benchmark.throughput_benchmark import run_throughput_benchmark
from backend.forensics.chain_of_custody import chain_manager

app = FastAPI(
    title="Unidirectional AI Cyber Threat Detection Enclave",
    description="Passive one-way IP traffic threat detection API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
if os.path.exists(FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

    @app.get("/")
    def read_root():
        return FileResponse(os.path.join(FRONTEND_DIST, "index.html"))

# Global engine and stream generator instances
engine = StreamingPipelineEngine()
generator = FlowStreamGenerator()

connected_websockets: List[WebSocket] = []
is_generator_running = True

def broadcast_alert(alert: StandardizedAlert):
    """Callback triggered whenever pipeline generates an alert."""
    alert_json = alert.model_dump_json()
    for ws in list(connected_websockets):
        try:
            asyncio.create_task(ws.send_text(alert_json))
        except Exception:
            pass

engine.register_alert_callback(broadcast_alert)

is_benchmark_active = False

async def stream_background_traffic():
    """Background task simulating continuous one-way traffic ingest (666+ FPS, ~2 Lakh flows in 5 min)."""
    counter = 0
    while is_generator_running:
        if not is_benchmark_active:
            flows = generator.generate_flow_batch(count=100)
            engine.process_batch(flows)
            counter += 1
            if counter % 3 == 0:
                try:
                    active_attacks = list(generator.active_attacks)
                    telem_data = engine.get_current_telemetry(active_attacks=active_attacks)
                    msg_json = json.dumps({"type": "telemetry", "data": telem_data})
                    for ws in list(connected_websockets):
                        try:
                            asyncio.create_task(ws.send_text(msg_json))
                        except Exception:
                            pass
                except Exception:
                    pass
        await asyncio.sleep(0.15)  # Continuous ingress stream

async def periodic_auto_archive():
    """Background periodic task checking live chain count and archiving older entries every 60s."""
    while is_generator_running:
        await asyncio.sleep(60.0)
        if not is_benchmark_active:
            try:
                stats = chain_manager.get_chain_stats()
                if stats["live_entries"] > chain_manager.max_live_entries:
                    chain_manager.archive_old_entries(keep_live_count=500)
            except Exception:
                pass

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(stream_background_traffic())
    asyncio.create_task(periodic_auto_archive())

class AttackRequest(BaseModel):
    attack_type: str  # ddos | c2_beaconing | dga_dns_tunnel | encrypted_malware | port_scan | exfiltration

@app.get("/api/status")
def get_status():
    return {
        "diode_status": "ONLINE",
        "ingest_mode": "Passive Mirror / Data Diode (READ-ONLY)",
        "return_path_connected": False,
        "write_back_blocked": True,
        "active_attack": generator.active_attack,
        "active_attacks": list(generator.active_attacks),
        "processed_flows": engine.total_processed_flows,
        "uptime_seconds": round(time.time() - engine.start_time, 1)
    }

@app.get("/api/alerts")
def get_alerts(
    threat_class: Optional[str] = None,
    severity: Optional[str] = None,
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = 100
):
    results = list(engine.alerts)
    if threat_class:
        results = [a for a in results if a.threat_class == threat_class]
    if severity:
        results = [a for a in results if a.severity == severity]
    if min_confidence > 0.0:
        results = [a for a in results if a.confidence_score >= min_confidence]

    return results[-limit:][::-1]

@app.get("/api/telemetry")
def get_telemetry():
    active_attacks = list(generator.active_attacks)
    return {
        "current": engine.get_current_telemetry(active_attacks=active_attacks),
        "history": list(engine.telemetry_history)
    }

@app.post("/api/traffic/attack")
def start_attack(req: AttackRequest):
    valid_attacks = ["ddos", "c2_beaconing", "dga_dns_tunnel", "encrypted_malware", "port_scan", "exfiltration"]
    if req.attack_type not in valid_attacks:
        return {"error": f"Invalid attack type. Must be one of {valid_attacks}"}

    active_list = generator.toggle_attack(req.attack_type)
    return {
        "status": "SUCCESS",
        "message": f"Toggled attack vector '{req.attack_type}'",
        "active_attacks": active_list
    }

@app.post("/api/traffic/all")
def start_all_attacks():
    all_attacks = ["ddos", "c2_beaconing", "dga_dns_tunnel", "encrypted_malware", "port_scan", "exfiltration"]
    active_list = generator.set_active_attacks(all_attacks)
    return {
        "status": "SUCCESS",
        "message": "Activated ALL 6 attack vectors simultaneously",
        "active_attacks": active_list
    }

@app.post("/api/traffic/stop")
def stop_attack():
    generator.set_active_attacks([])
    return {
        "status": "SUCCESS",
        "message": "Returned to standard benign background traffic profile",
        "active_attacks": []
    }

@app.post("/api/traffic/upload_pcap")
async def upload_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith(('.pcap', '.pcapng', '.cap')):
        return {"error": "Invalid file format. Please upload a .pcap or .pcapng file."}

    contents = await file.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        flows = list(PCAPStreamReader.read_pcap_file(tmp_path))
        if not flows:
            return {
                "status": "WARNING",
                "message": "No IP packet flows could be extracted from the uploaded PCAP file.",
                "filename": file.filename,
                "parsed_flows": 0,
                "alerts_detected": 0
            }

        alerts = engine.process_batch(flows)

        for alert in alerts:
            global_alerts.appendleft(alert)

        if alerts:
            await manager.broadcast({
                "type": "pcap_alerts",
                "alerts": [a.model_dump() for a in alerts]
            })

        return {
            "status": "SUCCESS",
            "filename": file.filename,
            "file_size_bytes": len(contents),
            "parsed_flows": len(flows),
            "alerts_detected": len(alerts),
            "detections": [a.model_dump() for a in alerts[:50]]
        }
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

@app.post("/api/benchmark")
async def run_benchmark(num_flows: int = 10000, simulate_fail: bool = False, use_live_state: bool = False):
    global is_benchmark_active
    is_benchmark_active = True
    await asyncio.sleep(0.2)  # Pause background streaming loop cleanly
    try:
        live_attacks = list(generator.active_attacks) if use_live_state else None
        report = await asyncio.to_thread(
            run_throughput_benchmark,
            num_flows=num_flows,
            simulate_fail=simulate_fail,
            use_live_state=use_live_state,
            live_attacks=live_attacks,
            batch_size=1000
        )
        return report
    finally:
        is_benchmark_active = False

@app.get("/api/chain/verify")
def verify_chain_of_custody(include_archive: bool = Query(True, description="Whether to include archived segments in verification")):
    """Verifies the complete SHA-256 cryptographic chain of custody for live and archived alerts."""
    return chain_manager.verify_chain(include_archive=include_archive)

@app.post("/api/chain/archive")
def archive_chain_of_custody(keep_live_count: Optional[int] = Query(None, description="Number of latest entries to retain in live DB")):
    """Moves older entries into chain_of_custody_archive.db without deleting evidence or breaking continuity."""
    return chain_manager.archive_old_entries(keep_live_count=keep_live_count)

@app.get("/api/chain/stats")
def get_chain_of_custody_stats():
    """Returns segmentation statistics across live and archived databases."""
    return chain_manager.get_chain_stats()

@app.post("/api/chain/tamper_test")
def tamper_chain_for_demo(sequence_number: int = 1):
    """Simulates an insider evidence tampering attack by modifying a stored alert row in SQLite."""
    return chain_manager.tamper_entry_for_test(sequence_number)

@app.post("/api/chain/reset")
def reset_chain_for_demo():
    """Resets the chain of custody database."""
    chain_manager.reset_chain()
    return {"status": "SUCCESS", "message": "Chain of custody database reset."}

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)
    try:
        while True:
            await asyncio.sleep(1.0)
            telemetry = engine.get_current_telemetry()
            await websocket.send_json({"type": "telemetry", "data": telemetry})
    except Exception:
        pass
    finally:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)
