import os
import sys
import subprocess
import uvicorn

def main():
    print("=" * 70)
    print("  VAJRARAKSHA: AI-BASED CYBER THREAT DETECTION IN UNIDIRECTIONAL IP TRAFFIC")
    print("=" * 70)

    project_root = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, project_root)

    # 1. Check ML Models
    models_dir = os.path.join(project_root, "backend", "models")
    c2_model = os.path.join(models_dir, "c2_isolation_forest.joblib")
    dga_model = os.path.join(models_dir, "dga_lgbm.joblib")
    malware_model = os.path.join(models_dir, "encrypted_malware_lgbm.joblib")

    if not (os.path.exists(c2_model) and os.path.exists(dga_model) and os.path.exists(malware_model)):
        print("[*] Pre-trained models missing. Training ML baseline models...")
        from backend.trainer import train_dga_model, train_c2_beaconing_model, train_encrypted_malware_model
        train_dga_model()
        train_c2_beaconing_model()
        train_encrypted_malware_model()
    else:
        print("[+] Pre-trained ML models verified in backend/models/")

    # 2. Check Frontend Build
    frontend_dist = os.path.join(project_root, "frontend", "dist")
    if not os.path.exists(frontend_dist):
        print("[*] Building React frontend static assets...")
        frontend_dir = os.path.join(project_root, "frontend")
        subprocess.run(["npm", "run", "build"], cwd=frontend_dir, shell=True, check=True)
    else:
        print("[+] React frontend static distribution bundle verified in frontend/dist/")

    # 3. Launch Server
    print("\n[+] Starting VajraRaksha Unidirectional AI Enclave Server on http://localhost:8000 ...")
    print("    - Dashboard UI:  http://localhost:8000")
    print("    - API Status:    http://localhost:8000/api/status")
    print("    - REST Alerts:   http://localhost:8000/api/alerts")
    print("    - WebSockets:    ws://localhost:8000/ws/alerts")
    print("=" * 70 + "\n")

    uvicorn.run("backend.api.server:app", host="0.0.0.0", port=8000, reload=False)

if __name__ == "__main__":
    main()
