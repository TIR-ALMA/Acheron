from flask import Flask, request, jsonify
from datetime import datetime
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

# Храним историю точек
location_history = []
public_key_hex = None  # Предполагаем, что публичный ключ будет установлен заранее

@app.route('/location', methods=['POST'])
def receive_location():
    data = request.get_json()
    
    if not data or 'aes' not in data or 'chacha' not in data or 'hash' not in data or 'signature' not in 
        return jsonify({"error": "Missing required fields"}), 400

    # Декодируем зашифрованные данные из hex
    try:
        aes_data = bytes.fromhex(data['aes'])
        chacha_data = bytes.fromhex(data['chacha'])
        received_hash = data['hash']
        signature = bytes.fromhex(data['signature'])
    except ValueError:
        return jsonify({"error": "Invalid hex data"}), 400

    # Проверяем подпись
    if public_key_hex:
        try:
            public_key_bytes = bytes.fromhex(public_key_hex)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, aes_data + chacha_data + received_hash.encode())
        except (ValueError, InvalidSignature):
            return jsonify({"error": "Invalid signature"}), 400
    else:
        print("⚠️ Public key not set, skipping signature verification")

    # Проверяем хеш
    computed_hash = hashes.Hash(hashes.SHA512())
    computed_hash.update(aes_data + chacha_data)
    expected_hash = computed_hash.finalize().hex()
    
    if received_hash != expected_hash:
        return jsonify({"error": "Hash mismatch"}), 400

    # Здесь мы предполагаем, что данные содержат координаты в каком-то формате
    # Так как данные зашифрованы, мы не можем их расшифровать без соответствующих ключей
    # Поэтому просто сохраняем зашифрованные данные
    location_entry = {
        'received_at': datetime.now().timestamp() * 1000,  # миллисекунды
        'aes_data_size': len(aes_data),
        'chacha_data_size': len(chacha_data),
        'hash': received_hash,
        'signature_valid': True
    }
    
    location_history.append(location_entry)
    print(f"📍 Новые зашифрованные данные получены: {location_entry}")
    return jsonify({"status": "OK"}), 200

@app.route('/latest-location', methods=['GET'])
def get_latest_location():
    if location_history:
        latest = location_history[-1]
        return jsonify(latest)
    else:
        return jsonify({"error": "No data yet"}), 404

@app.route('/history', methods=['GET'])
def get_full_history():
    return jsonify(location_history)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')  # HTTPS

