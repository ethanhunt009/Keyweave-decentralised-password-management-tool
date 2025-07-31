from flask import Flask, jsonify, request
import os
import json
import base64
import time
import config
from share_manager import ShareManager
from zk_protocols import ZKProofSystem

app = Flask(__name__)
manager = ShareManager()
zk_system = ZKProofSystem()

# Get port from environment or use default
port = int(os.environ.get("GUARDIAN_PORT", 5001))
node_id = f"guardian_{port}"

@app.route('/register-share', methods=['POST'])
def register_share():
    data = request.json
    share = base64.b64decode(data['share'])
    manager.store_share(
        vault_id=data['vault_id'],
        share_index=data['share_index'],
        share=share
    )
    return jsonify({"status": "registered", "guardian": node_id})

@app.route('/request-proof', methods=['POST'])
def request_proof():
    data = request.json
    recovery_id = data['recovery_id']
    
    # Get share for this recovery
    share_data = manager.get_share_for_recovery(recovery_id)
    if not share_data:
        return jsonify({"error": "Share not found"}), 404
    
    # Generate zero-knowledge proof
    challenge = os.urandom(config.Config.ZK_CHALLENGE_SIZE)
    proof = zk_system.generate_proof(share_data['share'], challenge)
    
    return jsonify({
        "proof": base64.b64encode(proof).decode('utf-8'),
        "challenge": base64.b64encode(challenge).decode('utf-8'),
        "share": base64.b64encode(share_data['share']).decode('utf-8'),
        "share_index": share_data['share_index'],
        "guardian_id": node_id
    })

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        "status": "active",
        "guardian_id": node_id,
        "port": port,
        "shares_stored": manager.count_shares()
    })

if __name__ == '__main__':
    app.run(
        host=config.Config.GUARDIAN_HOST, 
        port=port,
        threaded=True
    )