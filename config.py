# Global configuration for KeyWeave research prototype
import os

class Config:
    # Network settings
    VAULT_HOST = "localhost"
    VAULT_PORT = 5000
    GUARDIAN_HOST = "localhost"
    GUARDIAN_PORTS = [5001, 5002, 5003, 5004, 5005]  # Default ports for guardians
    
    # Cryptographic parameters
    SECRET_LENGTH = 32  # 256-bit secrets
    SHAMIR_PRIME = 2**256 - 2**32 - 977  # secp256k1 prime
    KDF_ITERATIONS = 100000
    ZK_CHALLENGE_SIZE = 32
    
    # System parameters
    GUARDIAN_TIMEOUT = 3600  # 1 hour inactivity timeout
    MAX_RECOVERY_ATTEMPTS = 5
    
    # Paths
    DATA_DIR = "data"
    VAULT_STORAGE = os.path.join(DATA_DIR, "vaults.json")
    GUARDIAN_STORAGE = os.path.join(DATA_DIR, "guardians")
    
    # Research parameters
    PERFORMANCE_SAMPLES = 100  # For benchmarking
    
    @classmethod
    def vault_url(cls):
        return f"http://{cls.VAULT_HOST}:{cls.VAULT_PORT}"
    
    @classmethod
    def guardian_url(cls, port):
        return f"http://{cls.GUARDIAN_HOST}:{port}"

# Create data directory if not exists
if not os.path.exists(Config.DATA_DIR):
    os.makedirs(Config.DATA_DIR)
if not os.path.exists(Config.GUARDIAN_STORAGE):
    os.makedirs(Config.GUARDIAN_STORAGE)