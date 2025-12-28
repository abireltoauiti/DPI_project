from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import threading
import json
from datetime import datetime
from werkzeug.security import check_password_hash

# ========== CHANGE 1: Import improved DPI functions ==========
# Replace 'dpi_model' with your improved DPI file name
from dpi_improved import (
    start_dpi, 
    stop_dpi as dpi_stop, 
    generate_report, 
    packet_data,
    REPORT_FILE,
    LOGFILE
)

app = Flask(__name__)
app.secret_key = "change_me_very_secure_key"   # à changer en production !

# ========== CHANGE 2: Enhanced DPI state management ==========
dpi_state = {
    'running': False,
    'thread': None,
    'interface': 'ens33',
    'filter': 'all',
    'start_time': None,
    'packet_count': 0
}

# ----------------- LOGIN (unchanged) -----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session["user_id"] = user[0]
            session["username"] = username
            session["role"] = user[2]
            return redirect(url_for("dashboard"))
        else:
            return "❌ Identifiants incorrects"
    return render_template("login.html")

# ----------------- DASHBOARD (unchanged) -----------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"]
    )

# ----------------- ADMIN LOGS (enhanced) -----------------
@app.route("/admin/logs")
def admin_logs():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    try:
        with open(LOGFILE, "r") as f:
            logs = f.read()
    except FileNotFoundError:
        logs = "Aucun log trouvé."
    
    # ========== NEW: Better HTML formatting ==========
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>DPI Logs</title>
        <style>
            body {{ font-family: monospace; padding: 20px; background: #1e1e1e; color: #d4d4d4; }}
            .alert {{ background: #3e1f1f; padding: 15px; margin: 10px 0; border-left: 4px solid #f44336; }}
            .back-btn {{ background: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; 
                         display: inline-block; margin-bottom: 20px; border-radius: 4px; }}
            pre {{ white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <a href="/dashboard" class="back-btn">← Retour au Dashboard</a>
        <h1>🔍 DPI Alert Logs</h1>
        <pre>{logs}</pre>
    </body>
    </html>
    """
    return html

# ========== CHANGE 3: Improved DPI start function ==========
def run_dpi_background(interface='ens33', filter_type='all', packet_limit=0):
    """Run DPI with the improved version"""
    global dpi_state
    dpi_state['running'] = True
    dpi_state['start_time'] = datetime.now()
    
    print(f"🔵 DPI démarré sur {interface} avec filtre '{filter_type}'")
    
    try:
        # Call improved DPI with parameters
        start_dpi(
            iface=interface,
            packet_count=packet_limit,
            filter_name=filter_type
        )
    except Exception as e:
        print(f"❌ Erreur DPI: {e}")
    finally:
        print("🔴 DPI arrêté.")
        dpi_state['running'] = False
        dpi_state['thread'] = None

# ========== CHANGE 4: Enhanced start route with options ==========
@app.route("/start_dpi", methods=["POST", "GET"])
def start_dpi_route():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    if dpi_state['running']:
        return jsonify({
            'status': 'error',
            'message': 'DPI déjà en cours'
        }), 400
    
    # ========== NEW: Get parameters from request ==========
    if request.method == "POST":
        data = request.get_json() if request.is_json else request.form
        interface = data.get('interface', 'ens33')
        filter_type = data.get('filter', 'all')
        packet_limit = int(data.get('packet_limit', 0))
    else:
        interface = 'ens33'
        filter_type = 'all'
        packet_limit = 0
    
    # Store config
    dpi_state['interface'] = interface
    dpi_state['filter'] = filter_type
    dpi_state['packet_count'] = packet_limit
    
    # Start DPI thread
    dpi_state['thread'] = threading.Thread(
        target=run_dpi_background,
        args=(interface, filter_type, packet_limit),
        daemon=True
    )
    dpi_state['thread'].start()
    
    if request.is_json:
        return jsonify({
            'status': 'success',
            'message': 'DPI lancé',
            'config': {
                'interface': interface,
                'filter': filter_type,
                'packet_limit': packet_limit
            }
        })
    else:
        return f"""
        ✅ DPI lancé en arrière-plan !<br>
        Interface: {interface}<br>
        Filtre: {filter_type}<br>
        <br><a href='/dashboard'>Retour</a>
        """

# ========== CHANGE 5: Improved stop route ==========
# ========== FIX: Stop route - Always return JSON ==========
@app.route("/stop_dpi", methods=["GET", "POST"])
def stop_dpi_route():
    if "user_id" not in session:
        return jsonify({'error': 'Not authenticated'}), 401  # ✅ JSON au lieu de redirect
    
    if not dpi_state['running']:
        return jsonify({'status': 'error', 'message': 'DPI non actif'}), 400  # ✅ Toujours JSON
    
    # Call improved DPI stop function
    dpi_stop()
    dpi_state['running'] = False
    
    # ✅ TOUJOURS retourner JSON (enlever le if/else)
    return jsonify({'status': 'success', 'message': 'DPI arrêté'})
# ========== NEW API ENDPOINTS ==========

@app.route("/api/dpi/status")
def dpi_status():
    """Get current DPI status - for real-time dashboard updates"""
    if "user_id" not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    status = {
        'running': dpi_state['running'],
        'interface': dpi_state['interface'],
        'filter': dpi_state['filter'],
        'start_time': dpi_state['start_time'].isoformat() if dpi_state['start_time'] else None,
        'packets_analyzed': len(packet_data),
        'current_time': datetime.now().isoformat()
    }
    
    # Calculate uptime if running
    if dpi_state['running'] and dpi_state['start_time']:
        uptime = (datetime.now() - dpi_state['start_time']).total_seconds()
        status['uptime_seconds'] = int(uptime)
    
    return jsonify(status)

@app.route("/api/dpi/stats")
def dpi_stats():
    """Get quick statistics for dashboard"""
    if "user_id" not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if not packet_data:
        return jsonify({
            'total': 0,
            'clean': 0,
            'warnings': 0,
            'critical': 0,
            'threat_score_total': 0
        })
    
    stats = {
        'total': len(packet_data),
        'clean': sum(1 for p in packet_data if p.get('threat_level') == 'ok'),
        'warnings': sum(1 for p in packet_data if p.get('threat_level') == 'warning'),
        'critical': sum(1 for p in packet_data if p.get('threat_level') == 'critical'),
        'threat_score_total': sum(p.get('threat_score', 0) for p in packet_data),
        'last_updated': datetime.now().isoformat()
    }
    
    return jsonify(stats)

@app.route("/api/dpi/alerts/recent")
def recent_alerts():
    """Get last 50 alerts (warning + critical)"""
    if "user_id" not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get recent packets (last 50)
    recent = packet_data[-50:] if packet_data else []
    
    # Filter only threats
    alerts = [
        {
            'timestamp': p.get('timestamp').isoformat() if p.get('timestamp') else None,
            'src_ip': p.get('src_ip'),
            'dst_ip': p.get('dst_ip'),
            'src_port': p.get('src_port'),
            'dst_port': p.get('dst_port'),
            'threat_level': p.get('threat_level'),
            'threat_score': p.get('threat_score'),
            'signatures': p.get('signatures', '').split(',') if p.get('signatures') else [],
            'anomalies': p.get('anomalies', '').split(',') if p.get('anomalies') else []
        }
        for p in recent
        if p.get('threat_level') in ['warning', 'critical']
    ]
    
    return jsonify({
        'alerts': alerts,
        'count': len(alerts)
    })

@app.route("/api/dpi/report")
def get_report():
    """Generate and return full pandas report"""
    if "user_id" not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        report = generate_report()
        return jsonify(report)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/dpi/report/download")
def download_report():
    """Download report as JSON file"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    try:
        # Generate fresh report
        generate_report()
        
        with open(REPORT_FILE, 'r') as f:
            report = json.load(f)
        
        response = jsonify(report)
        response.headers['Content-Disposition'] = f'attachment; filename=dpi_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        return response
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/dpi/logs/download")
def download_logs():
    """Download alert logs"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    try:
        with open(LOGFILE, 'r') as f:
            logs = f.read()
        
        return logs, 200, {
            'Content-Type': 'text/plain',
            'Content-Disposition': f'attachment; filename=dpi_alerts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        }
    except FileNotFoundError:
        return "No logs found", 404

# ========== NEW: Statistics page for visualizations ==========
@app.route("/stats")
def stats_page():
    """Statistics visualization page"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    return render_template("stats.html", username=session["username"])

# ========== LOGOUT ==========
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    print("="*60)
    print("🚀 DPI Flask Dashboard Starting")
    print("="*60)
    print("⚠️  IMPORTANT: Run with sudo for packet capture:")
    print("   sudo python3 app.py")
    print("="*60)
    print("📊 Available endpoints:")
    print("   /dashboard          - Main dashboard")
    print("   /start_dpi          - Start DPI scan")
    print("   /stop_dpi           - Stop DPI scan")
    print("   /admin/logs         - View alert logs")
    print("   /stats              - Statistics page")
    print("   /api/dpi/status     - DPI status (JSON)")
    print("   /api/dpi/stats      - Quick stats (JSON)")
    print("   /api/dpi/alerts/recent - Recent alerts (JSON)")
    print("   /api/dpi/report     - Full report (JSON)")
    print("="*60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
abir@abir-virtual-machine:~/dpi_project$ 

