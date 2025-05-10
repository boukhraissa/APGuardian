#!/usr/bin/env python3
"""dashboard_flask.py - Web interface for Gh0stN3t detector"""

from flask import Flask, render_template, jsonify, request
import os
import sys
import json
from datetime import datetime
import atexit
import subprocess
import threading
# Add the project root to the path to import log_parser
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)
import subprocess

# Import log parser
try:
    from log_parser import (
        get_alerts,
        get_info_logs,
        get_latest_attacks,
        get_attack_stats,
        get_log_summary,
        get_active_connections
    )
except ImportError as e:
    print(f"Error importing log_parser: {e}")
    sys.exit(1)

app = Flask(__name__)

# -------------------- Routes --------------------

@app.route('/')
def index():
    """Render the main dashboard page."""
    return render_template('dashboard.html')

@app.route('/test')
def test_api():
    """Test endpoint to verify API is working."""
    return jsonify({
        "status": "ok",
        "message": "API is running",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route('/api/logs/summary')
def api_logs_summary():
    """API endpoint to get a summary of all logs."""
    return jsonify(get_log_summary())

@app.route('/api/logs/alerts')
def api_alerts():
    """API endpoint to get alert logs."""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(get_alerts(max_entries=limit, force_refresh=True))

@app.route('/api/logs/info')
def api_info():
    """API endpoint to get info logs."""
    limit = request.args.get('limit', 100, type=int)
    return jsonify(get_info_logs(max_entries=limit, force_refresh=True))

@app.route('/api/connections/active')
def api_active_connections():

    try:
        connections = get_active_connections()
        return jsonify(connections)
    except Exception as e:
        app.logger.error(f"Error in active connections API: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/attacks/latest')
def api_latest_attacks():
    """API endpoint to get the latest detected attacks."""
    limit = request.args.get('limit', 10, type=int)
    return jsonify(get_latest_attacks(max_entries=limit))

@app.route('/api/attacks/stats')
def api_attack_stats():
    """API endpoint to get statistics about detected attacks."""
    return jsonify(get_attack_stats())

# ------------- Exit Handler -------------
def initialize_logs_on_exit():
    """Clear alert and info logs on shutdown."""
    log_dir = os.path.join(os.path.dirname(current_dir), "detector", "logs")
    alerts_log = os.path.join(log_dir, "alerts.log")
    info_log = os.path.join(log_dir, "info.log")

    os.makedirs(log_dir, exist_ok=True)
    open(alerts_log, "w").close()
    open(info_log, "w").close()

atexit.register(initialize_logs_on_exit)

# ------------- App Entry Point -------------
if __name__ == '__main__':
    print("Starting NetDefender dashboard on http://0.0.0.0:5000")
    log_dir = os.path.join(os.path.dirname(current_dir), "detector", "logs")
    alerts_log = os.path.join(log_dir, "alerts.log")
    info_log = os.path.join(log_dir, "info.log")

    print(f"Log files paths:")
    print(f"- Alerts log: {alerts_log} (exists: {os.path.exists(alerts_log)})")
    print(f"- Info log: {info_log} (exists: {os.path.exists(info_log)})")
    app.run(host='0.0.0.0', port=4444, debug=True)
