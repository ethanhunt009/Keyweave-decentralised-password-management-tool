import time
import statistics
from tqdm import tqdm
from shamir import ShamirSecretSharing
import os
import config

class PerformanceTest:
    def __init__(self):
        self.results = {
            "shamir_split": [],
            "shamir_recover": [],
            "encryption": [],
            "decryption": []
        }
    
    def run_shamir_tests(self, num_runs=config.Config.PERFORMANCE_SAMPLES):
        """Test Shamir's Secret Sharing performance"""
        print("\n=== Shamir's Secret Sharing Performance ===")
        secret = os.urandom(config.Config.SECRET_LENGTH)
        
        # Test splitting
        times = []
        for _ in tqdm(range(num_runs)):
            shamir = ShamirSecretSharing(threshold=3, total_shares=5)
            start = time.perf_counter()
            shares = shamir.split_secret(secret)
            end = time.perf_counter()
            times.append(end - start)
        self.results["shamir_split"] = times
        print(f"Split: {statistics.mean(times)*1000:.2f} ms avg")
        
        # Test recovery
        times = []
        for _ in tqdm(range(num_runs)):
            shamir = ShamirSecretSharing(threshold=3, total_shares=5)
            shares = shamir.split_secret(secret)
            start = time.perf_counter()
            shamir.recover_secret(shares[:3])
            end = time.perf_counter()
            times.append(end - start)
        self.results["shamir_recover"] = times
        print(f"Recover: {statistics.mean(times)*1000:.2f} ms avg")
    
    def run_crypto_tests(self, num_runs=config.Config.PERFORMANCE_SAMPLES):
        """Test encryption/decryption performance"""
        print("\n=== Encryption/Decryption Performance ===")
        from client.crypto_utils import encrypt_secret, decrypt_secret
        
        secret = os.urandom(config.Config.SECRET_LENGTH)
        key = os.urandom(32)  # AES-256 key
        
        # Encryption
        times = []
        for _ in tqdm(range(num_runs)):
            start = time.perf_counter()
            encrypted = encrypt_secret(secret, key)
            end = time.perf_counter()
            times.append(end - start)
        self.results["encryption"] = times
        print(f"Encrypt: {statistics.mean(times)*1000:.2f} ms avg")
        
        # Decryption
        encrypted = encrypt_secret(secret, key)
        times = []
        for _ in tqdm(range(num_runs)):
            start = time.perf_counter()
            decrypt_secret(encrypted, key)
            end = time.perf_counter()
            times.append(end - start)
        self.results["decryption"] = times
        print(f"Decrypt: {statistics.mean(times)*1000:.2f} ms avg")
    
    def save_results(self, filename="performance_results.json"):
        import json
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"Results saved to {filename}")

if __name__ == "__main__":
    tester = PerformanceTest()
    tester.run_shamir_tests()
    tester.run_crypto_tests()
    tester.save_results()