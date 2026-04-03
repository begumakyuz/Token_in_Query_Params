import os
import hmac
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)

# Çevre değişkenlerinden Token alınır (Fallback koyulur ancak testte maskelenir)
VALID_TOKEN = os.environ.get("API_SECRET_KEY", "secure_api_key_placeholder")

@app.route('/vulnerable/download', methods=['GET'])
def vulnerable_download():
    # L14 Zafiyeti (Adım 1): Token'ın doğrudan URL (Query Param) üzerinden alınması
    token = request.args.get('token')
    
    if token == VALID_TOKEN:
        return jsonify({"message": "Vulnerable Login Success", "data": "CONFIDENTIAL"})
    else:
        return jsonify({"error": "Unauthorized"}), 401


@app.route('/secure/download', methods=['GET'])
def secure_download():
    # Güvenli Mimari (Adım 5): Token sadece HTTP Header'dan alınmalıdır
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or Invalid Authorization Header"}), 401
    
    token = auth_header.split(" ")[1]
    
    # Timing Attack koruması
    if hmac.compare_digest(token, VALID_TOKEN):
        return jsonify({"message": "Secure Login Success", "data": "CONFIDENTIAL"})
    else:
        return jsonify({"error": "Access Denied"}), 403


if __name__ == '__main__':
    # Flask standart port 5000'de dinliyor olacak
    app.run(host='0.0.0.0', port=5000)
