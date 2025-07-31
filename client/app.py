import requests
import json
import base64
import config
from tabulate import tabulate
from crypto_utils import generate_secret, encrypt_secret, derive_key, decrypt_secret
from storage import SecureStorage

class KeyWeaveClient:
    def __init__(self):
        self.storage = SecureStorage()
        self.vault_url = config.Config.vault_url()
    
    def create_vault(self):
        print("\n=== Create New Vault ===")
        secret_name = input("Vault name: ")
        threshold = int(input("Recovery threshold (e.g., 3): "))
        num_guardians = int(input("Number of guardians (e.g., 5): "))
        
        # Generate cryptographic secret
        secret = generate_secret()
        print(f"Generated secret: {secret.hex()[:16]}...")
        
        # Create vault on coordinator
        response = requests.post(
            f"{self.vault_url}/vault/create",
            json={
                "secret_name": secret_name,
                "threshold": threshold,
                "num_guardians": num_guardians
            }
        )
        vault_data = response.json()
        vault_id = vault_data["vault_id"]
        
        # Initialize vault with secret
        response = requests.post(
            f"{self.vault_url}/vault/initialize",
            json={
                "vault_id": vault_id,
                "secret": base64.b64encode(secret).decode('utf-8')
            }
        )
        init_data = response.json()
        
        # Store encrypted secret locally
        password = input("Set vault password: ")
        salt = base64.b64decode(init_data["salt"])
        key = derive_key(password, salt)
        encrypted_secret = encrypt_secret(secret, key)
        
        self.storage.store_vault(
            vault_id=vault_id,
            encrypted_secret=base64.b64encode(encrypted_secret).decode('utf-8'),
            salt=init_data["salt"],
            commitment=init_data["commitment"],
            guardian_urls=init_data["guardian_urls"]
        )
        
        print(f"\nVault created successfully!")
        print(f"Vault ID: {vault_id}")
        print(f"Guardians: {', '.join(init_data['guardian_urls'])}")
        return vault_id
    
    def recover_secret(self, vault_id):
        vault_data = self.storage.get_vault(vault_id)
        if not vault_data:
            print("Vault not found!")
            return
        
        # Initiate recovery process
        response = requests.post(
            f"{self.vault_url}/vault/initiate-recovery",
            json={
                "vault_id": vault_id,
                "requester_id": "research_user"
            }
        )
        recovery_data = response.json()
        recovery_id = recovery_data["recovery_id"]
        
        print(f"Recovery initiated. Waiting for guardian responses...")
        
        # Perform recovery
        response = requests.post(
            f"{self.vault_url}/vault/perform-recovery",
            json={"recovery_id": recovery_id}
        )
        
        if response.status_code == 200:
            result = response.json()
            secret_b64 = result["recovered_secret"]
            secret = base64.b64decode(secret_b64)
            
            print("\nSecret recovered successfully!")
            print(f"Recovered secret: {secret.hex()[:16]}...")
            
            # Verify against stored commitment
            stored_commitment = vault_data["commitment"]
            verifier = hashes.Hash(hashes.SHA256())
            verifier.update(secret)
            computed_commitment = verifier.finalize().hex()
            
            if computed_commitment == stored_commitment:
                print("✓ Commitment verified!")
            else:
                print("⚠️ Commitment verification failed!")
            
            # Prompt to decrypt
            if input("Decrypt with password? (y/n): ").lower() == "y":
                password = input("Enter vault password: ")
                salt = base64.b64decode(vault_data["salt"])
                key = derive_key(password, salt)
                encrypted_secret = base64.b64decode(vault_data["encrypted_secret"])
                decrypted = decrypt_secret(encrypted_secret, key)
                
                if decrypted == secret:
                    print("✓ Local decryption successful!")
                    return decrypted
                else:
                    print("⚠️ Local decryption failed!")
            return secret
        else:
            print(f"Recovery failed: {response.text}")
            return None
    
    def list_vaults(self):
        return self.storage.list_vaults()

def main_menu():
    client = KeyWeaveClient()
    
    while True:
        print("\n===== KeyWeave Research Client =====")
        print("1. Create new vault")
        print("2. Recover secret from vault")
        print("3. List existing vaults")
        print("4. Exit")
        
        choice = input("> ")
        
        if choice == "1":
            client.create_vault()
        elif choice == "2":
            vault_id = input("Enter vault ID: ")
            client.recover_secret(vault_id)
        elif choice == "3":
            vaults = client.list_vaults()
            print("\nStored Vaults:")
            for i, vault_id in enumerate(vaults, 1):
                print(f"{i}. {vault_id}")
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main_menu()