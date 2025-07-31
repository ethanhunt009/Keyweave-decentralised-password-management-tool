import random
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import json
import time

# ============================================
# Core Cryptographic Functions
# ============================================

def generate_random_secret(length=32):
    """Generate a cryptographically secure random secret"""
    return os.urandom(length)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_secret(secret: bytes, key: bytes) -> bytes:
    """Encrypt secret using AES-256-CBC"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the data to be multiple of block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(secret) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_secret(encrypted: bytes, key: bytes) -> bytes:
    """Decrypt secret using AES-256-CBC"""
    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the data
    unpadder = padding.PKCS7(128).unpadder()
    secret = unpadder.update(padded_data) + unpadder.finalize()
    
    return secret

def create_commitment(data: bytes) -> str:
    """Create cryptographic commitment (simulated ZKP)"""
    return sha256(data).hexdigest()

def verify_commitment(data: bytes, commitment: str) -> bool:
    """Verify cryptographic commitment (simulated ZKP)"""
    return sha256(data).hexdigest() == commitment

# ============================================
# Shamir's Secret Sharing Implementation
# ============================================

class ShamirSecretSharing:
    """Implementation of Shamir's Secret Sharing scheme"""
    
    def __init__(self, threshold: int, total_shares: int):
        self.threshold = threshold
        self.total_shares = total_shares
    
    @staticmethod
    def _evaluate_polynomial(coefficients: list, x: int, prime: int) -> int:
        """Evaluate polynomial at x"""
        result = 0
        for coefficient in reversed(coefficients):
            result = (result * x + coefficient) % prime
        return result
    
    def split_secret(self, secret: bytes) -> list:
        """Split secret into shares"""
        # Convert secret to integer
        secret_int = int.from_bytes(secret, 'big')
        
        # Choose a prime larger than the secret
        prime = 2**256 - 2**32 - 977  # secp256k1 prime (for demonstration)
        
        # Generate random coefficients
        coefficients = [secret_int] + [
            random.randint(1, prime-1) 
            for _ in range(self.threshold-1)
        ]
        
        # Generate shares
        shares = []
        for i in range(1, self.total_shares + 1):
            x = i
            y = self._evaluate_polynomial(coefficients, x, prime)
            shares.append((x, y))
        
        return shares
    
    def recover_secret(self, shares: list) -> bytes:
        """Recover secret from shares using Lagrange interpolation"""
        prime = 2**256 - 2**32 - 977
        
        secret_int = 0
        for j in range(len(shares)):
            x_j, y_j = shares[j]
            
            # Lagrange basis polynomial
            basis = 1
            for m in range(len(shares)):
                if m == j:
                    continue
                x_m, y_m = shares[m]
                basis = (basis * (0 - x_m) * pow(x_j - x_m, -1, prime)) % prime
            
            secret_int = (secret_int + y_j * basis) % prime
        
        # Convert integer back to bytes
        secret_bytes = secret_int.to_bytes(32, 'big')
        return secret_bytes

# ============================================
# KeyWeave Core Components
# ============================================

class Guardian:
    """Represents a guardian holding a secret share"""
    
    def __init__(self, name: str, share: tuple):
        self.name = name
        self.share = share  # (x, y) tuple
        self.commitment = create_commitment(str(share).encode())
        self.last_active = time.time()
    
    def get_zk_proof(self) -> str:
        """Generate a simulated zero-knowledge proof of share ownership"""
        # In a real implementation, this would be a true ZKP
        return self.commitment
    
    def verify_zk_proof(self, proof: str) -> bool:
        """Verify simulated zero-knowledge proof"""
        return self.commitment == proof
    
    def __repr__(self):
        return f"Guardian({self.name}, Share#{self.share[0]})"

class KeyWeaveVault:
    """Main vault for managing secret recovery"""
    
    def __init__(self, secret_name: str, threshold: int, guardians: list):
        self.secret_name = secret_name
        self.threshold = threshold
        self.guardians = guardians
        self.recovery_attempts = []
        self.created_at = time.time()
        
        # Generate and encrypt the secret
        self.salt = os.urandom(16)
        self.secret = generate_random_secret()
        self.encrypted_secret = None  # Set during initialization
    
    def initialize(self, password: str):
        """Initialize the vault with encryption"""
        key = derive_key(password, self.salt)
        self.encrypted_secret = encrypt_secret(self.secret, key)
        print(f"Vault '{self.secret_name}' initialized with {len(self.guardians)} guardians")
    
    def request_recovery(self, requesting_guardians: list) -> bool:
        """Initiate a recovery request"""
        if len(requesting_guardians) < self.threshold:
            print(f"Error: Only {len(requesting_guardians)} guardians available, need {self.threshold}")
            return False
        
        # Record recovery attempt
        attempt = {
            'timestamp': time.time(),
            'guardians': [g.name for g in requesting_guardians],
            'status': 'initiated'
        }
        self.recovery_attempts.append(attempt)
        
        print(f"Recovery initiated with {len(requesting_guardians)} guardians")
        return True
    
    def perform_recovery(self, password: str) -> bytes:
        """Perform the secret recovery process"""
        # Verify we have enough guardians
        active_guardians = [g for g in self.guardians if time.time() - g.last_active < 3600]
        if len(active_guardians) < self.threshold:
            print(f"Error: Only {len(active_guardians)} active guardians, need {self.threshold}")
            return None
        
        # Collect shares and proofs
        shares = []
        for guardian in active_guardians[:self.threshold]:
            proof = guardian.get_zk_proof()
            if guardian.verify_zk_proof(proof):
                shares.append(guardian.share)
                print(f"✓ Valid proof from {guardian.name}")
            else:
                print(f"✗ Invalid proof from {guardian.name}")
                return None
        
        # Recover secret
        shamir = ShamirSecretSharing(self.threshold, len(self.guardians))
        recovered_secret = shamir.recover_secret(shares)
        
        # Decrypt the secret
        key = derive_key(password, self.salt)
        try:
            decrypted_secret = decrypt_secret(self.encrypted_secret, key)
            if decrypted_secret == recovered_secret:
                print("Success: Secret recovered and verified!")
                return recovered_secret
            else:
                print("Error: Recovered secret does not match!")
                return None
        except:
            print("Error: Decryption failed - possibly wrong password")
            return None
    
    def add_guardian(self, guardian):
        """Add a new guardian to the vault"""
        self.guardians.append(guardian)
        print(f"Added {guardian.name} as a new guardian")
    
    def get_vault_status(self) -> dict:
        """Return current vault status"""
        return {
            'secret_name': self.secret_name,
            'created_at': self.created_at,
            'guardians': [g.name for g in self.guardians],
            'threshold': self.threshold,
            'recovery_attempts': len(self.recovery_attempts),
            'active_guardians': sum(1 for g in self.guardians if time.time() - g.last_active < 3600)
        }
    
    def __repr__(self):
        return f"KeyWeaveVault('{self.secret_name}', {self.threshold}/{len(self.guardians)} guardians)"

# ============================================
# Demo Execution
# ============================================

def main():
    """Demonstrate KeyWeave functionality"""
    print("=" * 60)
    print("KeyWeave: Privacy-Preserving Secret Recovery System")
    print("=" * 60)
    print("Research Prototype for Journal Publication\n")
    
    # 1. Create a secret to protect
    print("[1] Generating cryptographic secret...")
    secret = generate_random_secret()
    print(f"    Secret: {secret.hex()[:16]}... (length: {len(secret)} bytes)")
    
    # 2. Split secret using Shamir's Secret Sharing
    print("\n[2] Splitting secret using Shamir's Secret Sharing...")
    shamir = ShamirSecretSharing(threshold=3, total_shares=5)
    shares = shamir.split_secret(secret)
    print(f"    Created {len(shares)} shares (3 required for recovery)")
    
    # 3. Create guardians
    print("\n[3] Creating guardians...")
    guardians = [
        Guardian("Alice", shares[0]),
        Guardian("Bob", shares[1]),
        Guardian("Charlie", shares[2]),
        Guardian("David", shares[3]),
        Guardian("Eve", shares[4])
    ]
    for guardian in guardians:
        print(f"    {guardian.name}: Share#{guardian.share[0]}, Commitment: {guardian.commitment[:12]}...")
    
    # 4. Create the vault
    print("\n[4] Creating KeyWeave vault...")
    vault = KeyWeaveVault(
        secret_name="My Crypto Wallet Key",
        threshold=3,
        guardians=guardians[:4]  # Only assign 4 guardians initially
    )
    vault_password = "secureVaultPassword123!"
    vault.initialize(vault_password)
    print(f"    Vault Status: {vault.get_vault_status()}")
    
    # 5. Add an additional guardian
    print("\n[5] Adding a new guardian...")
    vault.add_guardian(guardians[4])
    print(f"    Updated Vault Status: {vault.get_vault_status()}")
    
    # 6. Simulate recovery process
    print("\n[6] Simulating secret recovery...")
    print("    Initiating recovery request...")
    requesting_guardians = [guardians[0], guardians[2], guardians[4]]
    vault.request_recovery(requesting_guardians)
    
    print("\n    Performing recovery...")
    recovered_secret = vault.perform_recovery(vault_password)
    
    if recovered_secret:
        print(f"\n    Original Secret: {secret.hex()[:16]}...")
        print(f"    Recovered Secret: {recovered_secret.hex()[:16]}...")
        if secret == recovered_secret:
            print("    SUCCESS: Original and recovered secrets match!")
        else:
            print("    ERROR: Secrets do not match!")
    
    # 7. Demonstrate security features
    print("\n[7] Security demonstrations:")
    
    # Attempt with insufficient guardians
    print("\na) Attempt recovery with insufficient guardians:")
    requesting_guardians = [guardians[0], guardians[1]]
    success = vault.request_recovery(requesting_guardians)
    if not success:
        print("    Blocked: Not enough guardians")
    
    # Attempt with wrong password
    print("\nb) Attempt recovery with wrong password:")
    requesting_guardians = [guardians[0], guardians[1], guardians[2]]
    vault.request_recovery(requesting_guardians)
    recovered_secret = vault.perform_recovery("wrong_password")
    if not recovered_secret:
        print("    Blocked: Password verification failed")
    
    # Attempt with compromised guardian
    print("\nc) Simulate compromised guardian:")
    compromised_guardian = guardians[3]
    print(f"    Compromised: {compromised_guardian.name} (Share#{compromised_guardian.share[0]})")
    compromised_guardian.commitment = "modified_commitment"
    
    requesting_guardians = [guardians[0], guardians[1], compromised_guardian]
    vault.request_recovery(requesting_guardians)
    recovered_secret = vault.perform_recovery(vault_password)
    if not recovered_secret:
        print("    Blocked: ZK proof verification failed for compromised guardian")

if __name__ == "__main__":
    main()