import os
import json
import base64
import random
import config
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from shamir import ShamirSecretSharing

class KeyWeaveVault:
    def __init__(self):
        self.vaults = {}
        self.load_vaults()
    
    def load_vaults(self):
        if os.path.exists(config.Config.VAULT_STORAGE):
            with open(config.Config.VAULT_STORAGE, "r") as f:
                self.vaults = json.load(f)
    
    def save_vaults(self):
        with open(config.Config.VAULT_STORAGE, "w") as f:
            json.dump(self.vaults, f, indent=2)
    
    def create_vault(self, secret_name, threshold, num_guardians):
        vault_id = os.urandom(8).hex()
        self.vaults[vault_id] = {
            "secret_name": secret_name,
            "threshold": threshold,
            "num_guardians": num_guardians,
            "status": "created",
            "guardian_urls": [
                config.Config.guardian_url(port)
                for port in config.Config.GUARDIAN_PORTS[:num_guardians]
            ],
            "shares": {}
        }
        self.save_vaults()
        return vault_id
    
    def initialize_vault(self, vault_id, secret_b64):
        if vault_id not in self.vaults:
            return {"error": "Vault not found"}, 404
        
        secret = base64.b64decode(secret_b64)
        num_guardians = self.vaults[vault_id]["num_guardians"]
        threshold = self.vaults[vault_id]["threshold"]
        
        # Split secret
        shamir = ShamirSecretSharing(threshold, num_guardians)
        shares = shamir.split_secret(secret)
        
        # Store shares
        self.vaults[vault_id]["shares"] = {
            i: base64.b64encode(share).decode('utf-8')
            for i, share in enumerate(shares, 1)
        }
        
        # Create commitment
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(secret)
        commitment = digest.finalize().hex()
        
        # Update status
        self.vaults[vault_id]["status"] = "initialized"
        self.vaults[vault_id]["commitment"] = commitment
        self.vaults[vault_id]["salt"] = base64.b64encode(os.urandom(16)).decode('utf-8')
        self.save_vaults()
        
        return {
            "salt": self.vaults[vault_id]["salt"],
            "commitment": commitment,
            "guardian_urls": self.vaults[vault_id]["guardian_urls"]
        }
    
    def initiate_recovery(self, vault_id, requester_id):
        if vault_id not in self.vaults:
            return None
        
        recovery_id = os.urandom(8).hex()
        self.vaults[vault_id].setdefault("recoveries", {})[recovery_id] = {
            "requester_id": requester_id,
            "status": "initiated",
            "timestamp": time.time()
        }
        self.save_vaults()
        return recovery_id
    
    def reconstruct_secret(self, vault_id, shares_b64):
        if vault_id not in self.vaults:
            return None
        
        # Convert shares to bytes
        shares = [base64.b64decode(share) for share in shares_b64]
        
        # Reconstruct secret
        threshold = self.vaults[vault_id]["threshold"]
        num_guardians = self.vaults[vault_id]["num_guardians"]
        shamir = ShamirSecretSharing(threshold, num_guardians)
        secret = shamir.recover_secret(shares)
        return base64.b64encode(secret).decode('utf-8')
    
    def get_guardian_urls(self, vault_id):
        return self.vaults.get(vault_id, {}).get("guardian_urls", [])
    
    def get_threshold(self, vault_id):
        return self.vaults.get(vault_id, {}).get("threshold", 0)
    
    def get_vault_status(self, vault_id):
        vault = self.vaults.get(vault_id)
        if not vault:
            return None
        
        return {
            "secret_name": vault["secret_name"],
            "status": vault["status"],
            "created": vault.get("timestamp", time.time()),
            "last_recovery": max(vault.get("recoveries", {}).keys(), default=None),
            "guardian_count": len(vault["guardian_urls"]),
            "active": True
        }
    
    def verify_guardian_proof(self, vault_id, proof_data):
        # In a real implementation, this would verify a true ZKP
        # For research purposes, we simulate verification
        return random.random() > 0.2  # 80% success rate simulation
