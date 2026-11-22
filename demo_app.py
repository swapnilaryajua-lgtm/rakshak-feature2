"""CyberSentinel Live Demo Server.

Serves the offline, interactive presentation-grade SOC dashboard for the Jaypee Agentic AI Summit.
Provides REST API endpoints for live pipeline re-execution, replay state telemetry,
Gantt policy tracking, agreement diagnostics, what-if simulations, and official submission validation.

Usage:
    python demo_app.py               # Runs fresh pipeline, launches server, opens browser
    python demo_app.py --precomputed # Launches instantly using cached outputs/demo/replay_demo.json
"""

import sys
import os
import json
import socket
import argparse
import webbrowser
import threading
import time
from typing import Dict, Any, List, Optional
from pathlib import Path
from flask import Flask, jsonify, send_from_directory, request

import config
from demo_data import run_demo_pipeline

# Base directories
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DEMO_DIR = BASE_DIR / "outputs" / "demo"
DEMO_JSON = DEMO_DIR / "replay_demo.json"

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")


def get_cached_or_generate_data() -> Dict:
    """Returns cached demo JSON if present, otherwise generates it fresh."""
    if DEMO_JSON.exists():
        try:
            with open(DEMO_JSON, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[Server] Error reading cache ({e}), recomputing...")
    return run_demo_pipeline()


@app.route("/")
def index():
    """Serves the single-page application."""
    return send_from_directory(str(STATIC_DIR), "index.html")


@app.route("/api/replay", methods=["GET"])
def api_replay():
    """Returns the full master replay JSON (records, policies, agents, counters)."""
    data = get_cached_or_generate_data()
    return jsonify(data)


@app.route("/api/summary", methods=["GET"])
def api_summary():
    """Returns high-level executive summary metrics."""
    data = get_cached_or_generate_data()
    return jsonify({
        "metadata": data.get("metadata", {}),
        "summary": data.get("summary", {})
    })


@app.route("/api/validate", methods=["GET"])
def api_validate():
    """Returns official validator results (15/15 checks) and file comparison."""
    data = get_cached_or_generate_data()
    return jsonify({
        "validation_checks": data.get("validation_checks", []),
        "matches_submitted_files": data.get("summary", {}).get("matches_submitted_files", False),
        "mismatch_details": data.get("summary", {}).get("mismatch_details", []),
        "all_checks_passed": data.get("summary", {}).get("all_checks_passed", False)
    })


@app.route("/api/whatif", methods=["GET"])
def api_whatif():
    """Returns the interactive 'what if' policy parameter simulation matrix."""
    data = get_cached_or_generate_data()
    return jsonify({
        "what_if_matrix": data.get("what_if_matrix", [])
    })


@app.route("/api/run", methods=["POST"])
def api_run():
    """Triggered by the 'Run Fresh Replay' UI button. Executes pipeline live and returns updated payload."""
    try:
        print("\n[Server] Live replay requested from UI...")
        t0 = time.time()
        fresh_data = run_demo_pipeline()
        elapsed = time.time() - t0
        print(f"[Server] Replay completed in {elapsed:.2f}s.")
        return jsonify({
            "status": "success",
            "elapsed": round(elapsed, 2),
            "data": fresh_data
        })
    except Exception as e:
        print(f"[Server] Error during live replay: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


def find_free_port(start_port: int = 5000, max_attempts: int = 50) -> int:
    """Finds an available TCP port starting from start_port."""
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start_port


def main():
    parser = argparse.ArgumentParser(description="CyberSentinel Live Demo App")
    parser.add_argument("--precomputed", action="store_true", help="Launch instantly using precomputed data")
    parser.add_argument("--port", type=int, default=5000, help="Port to run server on")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")
    args = parser.parse_args()

    port = find_free_port(args.port)
    url = f"http://{args.host}:{port}"

    print("=" * 80)
    print("  CYBERSENTINEL: MULTI-AGENT INTRUSION DETECTION & ADAPTIVE DEFENSE")
    print("  Official Live Demonstration Server (Jaypee Agentic AI Summit 2026)")
    print("=" * 80)

    # Pre-computation step
    if not args.precomputed or not DEMO_JSON.exists():
        print("[Startup] Running pipeline on records.csv...")
        run_demo_pipeline()
    else:
        print(f"[Startup] Using precomputed cached data from {DEMO_JSON}")

    print(f"\n[Ready] Server live at: {url}")
    print("  -> Press Ctrl+C in terminal to stop server.\n")

    if not args.no_browser:
        def open_browser():
            import time
            time.sleep(1.0)
            webbrowser.open(url)
        threading.Thread(target=open_browser, daemon=True).start()

    app.run(host=args.host, port=port, debug=False)


if __name__ == "__main__":
    import time
    main()
