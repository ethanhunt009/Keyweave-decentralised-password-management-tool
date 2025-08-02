import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from keyweave.crypto import shamir_split_secret, shamir_reconstruct_secret

class KeyWeaveNetwork:
    """
    Orchestrates the KeyWeave process, acting as the decentralized network.
    Uses IPFS to store encrypted shards with RSA encryption.
    """
    def __init__(self):
        self.guardian_commitments = {}
        self.api_url = "http://127.0.0.1:5001"

    def add_to_ipfs(self, data: bytes) -> str:
        try:
            files = {'file': ('shard.txt', data)}
            response = requests.post(f"{self.api_url}/api/v0/add", files=files, timeout=5)
            response.raise_for_status()
            return response.json()["Hash"]
        except requests.exceptions.ConnectionError:
            print("\n❌ ERROR: Could not connect to IPFS daemon at http://127.0.0.1:5001")
            print("Please start IPFS with: 'ipfs daemon'")
            raise
        except Exception as e:
            print(f"\n❌ ERROR: Failed to add data to IPFS: {e}")
            raise

    def setup_escrow(self, secret, policy, guardians) -> bool:
        """Splits and encrypts the secret, uploads to IPFS, and distributes CIDs."""
        print("\n--- Initiating KeyWeave Setup ---")
        
        # First check if IPFS is running
        try:
            test_response = requests.post(f"{self.api_url}/api/v0/version", timeout=2)
            test_response.raise_for_status()
            print(f"[IPFS] Connected to IPFS node (version {test_response.json()['Version']})")
        except requests.exceptions.ConnectionError:
            print("\n❌ IPFS CONNECTION FAILED: Daemon not running")
            print("Run 'ipfs daemon' in a separate terminal")
            return False
        except Exception as e:
            print(f"\n❌ ERROR: IPFS connection test failed: {e}")
            return False

        if policy.num_guardians != len(guardians):
            print("Policy must match the number of provided guardians.")
            return False

        try:
            shares = shamir_split_secret(secret, policy.threshold, policy.num_guardians)
            print(f"[KeyWeave] Secret split into {len(shares)} shares.")

            for i, guardian in enumerate(guardians):
                x, y = shares[i]
                shard_string = f"{x},{y}"
                
                # Encrypt shard with guardian's public key
                public_key = serialization.load_pem_public_key(
                    guardian.public_key.encode('utf-8')
                )
                encrypted = public_key.encrypt(
                    shard_string.encode('utf-8'),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                cid = self.add_to_ipfs(encrypted)
                print(f"[IPFS] Uploaded RSA-encrypted shard for {guardian.name}, CID: {cid}")
                guardian.receive_shard_ipfs(cid)

                self.guardian_commitments[guardian.did] = guardian.commitment

            print("[KeyWeave] All shares encrypted, uploaded to IPFS, and commitments recorded.")
            return True
        except Exception as e:
            print(f"\n❌ Setup failed: {e}")
            return False

    def initiate_recovery(self, recovery_guardians, policy):
        """Verifies guardian proofs and reconstructs the secret if threshold is met."""
        print(f"\n--- Initiating KeyWeave Recovery for {len(recovery_guardians)} guardians ---")
        if len(recovery_guardians) < policy.threshold:
            print(f"[KeyWeave] RECOVERY FAILED: Not enough guardians. Need {policy.threshold}, got {len(recovery_guardians)}.")
            return None

        valid_proofs = 0
        shards_for_reconstruction = []

        print(f"[KeyWeave] Collecting and verifying proofs...")
        for guardian in recovery_guardians:
            proof = guardian.provide_proof()
            guardian_did = proof["did"]
            guardian_commitment = proof["commitment"]

            if guardian_did in policy.authorized_dids and self.guardian_commitments.get(guardian_did) == guardian_commitment:
                print(f"  [KeyWeave] Proof from Guardian {guardian.name} ({guardian_did[:10]}...) is VALID.")
                valid_proofs += 1
                shards_for_reconstruction.append(guardian.provide_shard_for_reconstruction())
            else:
                print(f"  [KeyWeave] Proof from Guardian {guardian.name} is INVALID.")

        if valid_proofs >= policy.threshold:
            print(f"[KeyWeave] Success! {valid_proofs} valid proofs collected, meeting the threshold of {policy.threshold}.")
            reconstructed_secret = shamir_reconstruct_secret(shards_for_reconstruction)
            print("[KeyWeave] RECOVERY SUCCESSFUL!")
            return reconstructed_secret
        else:
            print(f"[KeyWeave] RECOVERY FAILED: Only {valid_proofs} valid proofs, but threshold is {policy.threshold}.")
            return None