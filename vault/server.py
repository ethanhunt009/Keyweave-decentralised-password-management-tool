from flask import Flask, jsonify, request
from flask_cors import CORS
from vault_core import KeyWeaveVault
from recovery_tracker import RecoveryTracker
import config

app = Flask(__name__)
CORS(app)  # Enable CORS for research flexibility
vault = KeyWeaveVault()
tracker = RecoveryTracker()

@app.route('/vault/create', methods=['POST'])
def create_vault():
    data = request.json
    vault_id = vault.create_vault(
        secret_name=data['secret_name'],
        threshold=data['threshold'],
        num_guardians=data['num_guardians']
    )
    return jsonify({"vault_id": vault_id, "status": "created"})

@app.route('/vault/initialize', methods=['POST'])
def initialize_vault():
    data = request.json
    result = vault.initialize_vault(
        vault_id=data['vault_id'],
        secret=data['secret']  # Base64 encoded
    )
    return jsonify(result)

@app.route('/vault/initiate-recovery', methods=['POST'])
def initiate_recovery():
    data = request.json
    recovery_id = vault.initiate_recovery(
        vault_id=data['vault_id'],
        requester_id=data['requester_id']
    )
    tracker.log_recovery_start(recovery_id)
    return jsonify({"recovery_id": recovery_id})

@app.route('/vault/perform-recovery', methods=['POST'])
def perform_recovery():
    data = request.json
    recovery_id = data['recovery_id']
    
    # Get recovery data
    recovery_data = tracker.get_recovery(recovery_id)
    if not recovery_data:
        return jsonify({"error": "Invalid recovery ID"}), 400
    
    vault_id = recovery_data["vault_id"]
    
    # Collect shares from guardians
    shares = []
    for guardian_url in vault.get_guardian_urls(vault_id):
        try:
            # Request proof from guardian
            response = requests.post(
                f"{guardian_url}/request-proof",
                json={"recovery_id": recovery_id},
                timeout=5
            )
            if response.status_code == 200:
                proof_data = response.json()
                if vault.verify_guardian_proof(vault_id, proof_data):
                    shares.append(proof_data["share"])
                    tracker.log_guardian_response(recovery_id, guardian_url, True)
                else:
                    tracker.log_guardian_response(recovery_id, guardian_url, False)
            else:
                tracker.log_guardian_response(recovery_id, guardian_url, False)
        except requests.exceptions.RequestException:
            tracker.log_guardian_response(recovery_id, guardian_url, False)
    
    # Reconstruct secret
    if len(shares) >= vault.get_threshold(vault_id):
        secret = vault.reconstruct_secret(vault_id, shares)
        tracker.log_recovery_success(recovery_id)
        return jsonify({"recovered_secret": secret})  # Base64 encoded
    else:
        tracker.log_recovery_failure(recovery_id)
        return jsonify({"error": "Insufficient valid shares"}), 400

@app.route('/vault/status/<vault_id>', methods=['GET'])
def vault_status(vault_id):
    status = vault.get_vault_status(vault_id)
    if status:
        return jsonify(status)
    return jsonify({"error": "Vault not found"}), 404

@app.route('/vault/audit/<recovery_id>', methods=['GET'])
def recovery_audit(recovery_id):
    log = tracker.get_log(recovery_id)
    if log:
        return jsonify(log)
    return jsonify({"error": "Recovery not found"}), 404

if __name__ == '__main__':
    app.run(
        host=config.Config.VAULT_HOST, 
        port=config.Config.VAULT_PORT,
        threaded=True
    )