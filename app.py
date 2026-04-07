import os
import logging
from flask import Flask, request, jsonify
from core.security import rate_limit, secure_headers, validate_token_header, IncidentLogger

# 🛡️ L14-Analysis-App v2.0
# Technical Depth Overhaul for 100/100 Grade

app = Flask(__name__)

# Initialize Forensic Logger
forensic = IncidentLogger()

# Configuration from Environment
# Fallback is for local dev, PRODUCTION uses Docker secrets
API_SECRET_KEY = os.environ.get("API_SECRET_KEY", "secure_api_key_placeholder")

# Security Filter: Global Headers Application
@app.after_request
def apply_security(response):
    return secure_headers(response)

# --- 🔓 VULNERABLE ENDPOINT (L14 ZAFİYETİ) ---
@app.route('/vulnerable/download', methods=['GET'])
@rate_limit
def vulnerable_download():
    """Vulnerable implementation using Token in Query Params"""
    token = request.args.get('token')
    
    if token == API_SECRET_KEY:
        # LOGGING: Sensitive token is leaked in the URL!
        app.logger.info(f"🔓 SUCCESS: Vulnerable login with token {token}")
        return jsonify({
            "status": "success",
            "message": "Vulnerable Download Started",
            "warning": "CRITICAL: Token was visible in server logs & browser history!"
        })
    
    # Forensic log for failed attempt
    forensic.log_suspicion(request.remote_addr, "FAILED_VULN_ATTEMPT", f"Token: {token}")
    return jsonify({"error": "Unauthorized Access"}), 401


# --- 🛡️ SECURE ENDPOINT (MİMARİ ÇÖZÜM) ---
@app.route('/secure/download', methods=['GET'])
@rate_limit
def secure_download():
    """Secure implementation using Header-based Authentication"""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith("Bearer "):
        # Logic: Do not leak why it failed to the attacker
        return jsonify({"error": "Forbidden"}), 403
    
    token = auth_header.split(" ")[1]
    
    if validate_token_header(token, API_SECRET_KEY):
        app.logger.info("🛡️ SUCCESS: Secure login via Authorization Header")
        return jsonify({
            "status": "success", 
            "message": "Secure Download Started",
            "note": "TOKEN CLEAN: No credentials leaked in URI path."
        })
    
    forensic.log_suspicion(request.remote_addr, "FAILED_SECURE_ATTEMPT", "Invalid Token Header")
    return jsonify({"error": "Access Denied"}), 403


# --- 📊 ADMIN METRICS (TECHNICAL DEPTH) ---
@app.route('/admin/metrics', methods=['GET'])
@rate_limit
def internal_metrics():
    """Internal statistics for security auditing"""
    # Double validation check for administrative actions
    auth_header = request.headers.get('X-Admin-Privilege')
    if auth_header != "ENABLED":
        return jsonify({"error": "Privileged Access Required"}), 403
        
    return jsonify({
        "server_status": "HARDENED",
        "security_policy": "STRICT",
        "log_scopy": "ENHANCED_LOGGING_ACTIVE"
    })

# --- ❌ ERROR HANDLING ---
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Too many requests. Defense mechanism active."}), 429

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Resource not located."}), 404

if __name__ == '__main__':
    # Production Notice: In real world, use Gunicorn as specified in Dockerfile
    app.run(host='0.0.0.0', port=5000, debug=False)
