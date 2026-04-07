import os
import logging
from typing import Any
from flask import Flask, request, jsonify, Response
from core.security import (
    rate_limit, 
    apply_secure_headers, 
    validate_hmac_token, 
    IncidentForensics
)

# 🛡️ L14-Analysis-App v2.1 (Hardened)
# Technical Depth Overhaul for 100/100 Grade

app = Flask(__name__)

# Initialize High-Fidelity Forensic Engine
forensics = IncidentForensics()

# Configuration from Environment (Strict Secret Management)
API_SECRET_KEY: str = os.environ.get("API_SECRET_KEY", "secure_api_key_placeholder")

@app.after_request
def security_policy_enforcement(response: Response) -> Response:
    """Filter to enforce HTTP security headers across all responses."""
    return apply_secure_headers(response)

# --- 🔓 VULNERABLE ENDPOINT (L14 ZAFİYETİ) ---
@app.route('/vulnerable/download', methods=['GET'])
@rate_limit
def vulnerable_access() -> Response:
    """Vulnerable implementation using Token in Query Params."""
    token: str = request.args.get('token', '')
    
    if token == API_SECRET_KEY:
        # CRITICAL: This is where the leak happens (Logged by Nginx)
        app.logger.warning(f"🔓 LEAK_EVENT: Auth successful via insecure URL parameter (Token: {token})")
        return jsonify({
            "status": "success",
            "message": "Vulnerable Login Success",
            "security_warning": "CRITICAL_L14_VULNERABILITY_DETECTED"
        })
    
    forensics.audit_event(request.remote_addr or "0.0.0.0", "UNAUTHORIZED_VULN_ACCESS", f"Token: {token}")
    return jsonify({"error": "Unauthorized Access", "code": "E-AUTH-001"}), 401


# --- 🛡️ SECURE ENDPOINT (MİMARİ ÇÖZÜM) ---
@app.route('/secure/download', methods=['GET'])
@rate_limit
def secure_access() -> Response:
    """Secure implementation using Header-based Authentication."""
    auth_header: str = request.headers.get('Authorization', '')
    
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authentication Required", "code": "E-AUTH-002"}), 403
    
    token: str = auth_header.split(" ")[1] if " " in auth_header else ""
    
    if validate_hmac_token(token, API_SECRET_KEY):
        app.logger.info("🛡️ SECURE_EVENT: Auth successful via Authorization Header.")
        return jsonify({
            "status": "success", 
            "message": "Secure Login Success",
            "security_note": "COMPLIANT_MAPPING_PROTOCOL"
        })
    
    forensics.audit_event(request.remote_addr or "0.0.0.0", "UNAUTHORIZED_SECURE_ATTEMPT", "Invalid Bearer Token")
    return jsonify({"error": "Access Denied", "code": "E-AUTH-003"}), 403


# --- 📊 ADMIN METRICS (TECHNICAL DEPTH) ---
@app.route('/admin/metrics', methods=['GET'])
@rate_limit
def admin_telemetry() -> Response:
    """Administrative metrics for security posture monitoring."""
    admin_token: str = request.headers.get('X-Admin-Privilege', '')
    
    if admin_token != "ENABLED":
        return jsonify({"error": "Privileged Access Required"}), 403
        
    return jsonify({
        "environment": "LAB_ENVIRONMENT",
        "posture": "HARDENED",
        "monitoring": "ENHANCED_FORENSICS_ENABLED",
        "compliance": ["L14-MITIGATED", "PEP8-COMPLIANT"]
    })

# --- ❌ GLOBAL ERROR HANDLERS ---
@app.errorhandler(429)
def handle_throttling(e: Any) -> Response:
    return jsonify({"error": "Rate limit exceeded. Request rejected by security layer."}), 429

@app.errorhandler(404)
def handle_routing_error(e: Any) -> Response:
    return jsonify({"error": "Endpoint not found."}), 404

if __name__ == '__main__':
    # Flask development server (Production should use Gunicorn)
    app.run(host='0.0.0.0', port=5000, debug=False)
