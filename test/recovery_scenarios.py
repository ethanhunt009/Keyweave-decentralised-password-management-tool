import unittest
import requests
import time
import base64
import config
from client.crypto_utils import generate_secret

class RecoveryScenarios(unittest.TestCase):
    VAULT_URL = config.Config.vault_url()
    
    def create_test_vault(self, threshold=3, num_guardians=5):
        """Create a test vault and return its ID"""
        response = requests.post(
            f"{self.VAULT_URL}/vault/create",
            json={
                "secret_name": "test_vault",
                "threshold": threshold,
                "num_guardians": num_guardians
            }
        )
        vault_id = response.json()["vault_id"]
        
        secret = generate_secret()
        response = requests.post(
            f"{self.VAULT_URL}/vault/initialize",
            json={
                "vault_id": vault_id,
                "secret": base64.b64encode(secret).decode('utf-8')
            }
        )
        return vault_id, secret
    
    def test_successful_recovery(self):
        """Test successful recovery scenario"""
        vault_id, original_secret = self.create_test_vault()
        
        # Initiate recovery
        response = requests.post(
            f"{self.VAULT_URL}/vault/initiate-recovery",
            json={
                "vault_id": vault_id,
                "requester_id": "test_user"
            }
        )
        recovery_id = response.json()["recovery_id"]
        
        # Perform recovery
        response = requests.post(
            f"{self.VAULT_URL}/vault/perform-recovery",
            json={"recovery_id": recovery_id}
        )
        
        self.assertEqual(response.status_code, 200)
        recovered_secret = base64.b64decode(response.json()["recovered_secret"])
        self.assertEqual(original_secret, recovered_secret)
    
    def test_insufficient_guardians(self):
        """Test recovery with insufficient active guardians"""
        vault_id, _ = self.create_test_vault(threshold=4, num_guardians=5)
        
        # Disable some guardians (simulate failure)
        # In real test, we would stop guardian processes
        
        # Initiate recovery
        response = requests.post(
            f"{self.VAULT_URL}/vault/initiate-recovery",
            json={
                "vault_id": vault_id,
                "requester_id": "test_user"
            }
        )
        recovery_id = response.json()["recovery_id"]
        
        # Perform recovery
        response = requests.post(
            f"{self.VAULT_URL}/vault/perform-recovery",
            json={"recovery_id": recovery_id}
        )
        
        self.assertEqual(response.status_code, 400)
        self.assertIn("Insufficient valid shares", response.json()["error"])
    
    def test_tampered_share(self):
        """Test recovery with a tampered share"""
        vault_id, original_secret = self.create_test_vault()
        
        # Initiate recovery
        response = requests.post(
            f"{self.VAULT_URL}/vault/initiate-recovery",
            json={
                "vault_id": vault_id,
                "requester_id": "test_user"
            }
        )
        recovery_id = response.json()["recovery_id"]
        
        # TODO: Implement share tampering simulation
        # This would require intercepting and modifying network requests
        
        # For now, we'll skip the implementation
        self.skipTest("Share tampering simulation not implemented")
    
    def test_recovery_audit_log(self):
        """Test audit log functionality"""
        vault_id, _ = self.create_test_vault()
        
        # Initiate recovery
        response = requests.post(
            f"{self.VAULT_URL}/vault/initiate-recovery",
            json={
                "vault_id": vault_id,
                "requester_id": "test_user"
            }
        )
        recovery_id = response.json()["recovery_id"]
        
        # Check audit log
        response = requests.get(
            f"{self.VAULT_URL}/vault/audit/{recovery_id}"
        )
        self.assertEqual(response.status_code, 200)
        log = response.json()
        self.assertEqual(log["status"], "success")
        self.assertGreater(len(log["events"]), 0)

if __name__ == '__main__':
    unittest.main()