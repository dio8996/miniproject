"""
ZeroAttack – Intelligent Rule-Based Cyber Attack Detection and Prevention System
Main Flask Application Server
"""

import os
from flask import Flask, jsonify, render_template, send_from_directory
from flask_cors import CORS
from config import Config
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.events import events_bp
from routes.rules import rules_bp
from routes.ips import ips_bp
from routes.users import users_bp

def create_app():
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static"
    )
    app.config.from_object(Config)

    # Enable CORS for clean REST API decoupling
    CORS(app, supports_credentials=True)

    # Register API Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(ips_bp)
    app.register_blueprint(users_bp)

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/login")
    def login_page():
        return render_template("login.html")

    @app.route("/register")
    def register_page():
        return render_template("register.html")

    @app.route("/monitor")
    def monitor_page():
        return render_template("monitor.html")

    @app.route("/events")
    def events_page():
        return render_template("events.html")

    @app.route("/events/<int:event_id>")
    def event_details_page(event_id):
        return render_template("event_details.html", event_id=event_id)

    @app.route("/ips")
    def ips_page():
        return render_template("ips.html")

    @app.route("/rules")
    def rules_page():
        return render_template("rules.html")

    @app.route("/users")
    def users_page():
        return render_template("users.html")

    @app.route("/reports")
    def reports_page():
        return render_template("reports.html")

    @app.route("/audit")
    def audit_page():
        return render_template("audit.html")

    @app.route("/api/health")
    def health_check():
        return jsonify({
            "status": "OPERATIONAL",
            "system": "ZeroAttack Cyber Attack Detection Engine",
            "version": "1.0.0",
            "engine": {
                "rule_engine": "ACTIVE",
                "anomaly_detector": "ACTIVE",
                "risk_scoring": "ACTIVE",
                "payload_encryption": "AES-256-GCM"
            }
        })

    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.getenv("PORT", 5000))
    print(f"================================================================")
    print(f"[*] ZeroAttack Cyber Defense System starting on port {port}...")
    print(f"[*] Access dashboard: http://127.0.0.1:{port}")
    print(f"================================================================")
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG)
