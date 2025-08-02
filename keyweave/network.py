import requests
from cryptography.fernet import Fernet
from keyweave.crypto import shamir_split_secret, shamir_reconstruct_secret
from keyweave.entities import FERNET_KEY

class KeyWeaveNetwork:
    """
    Orchestrates the KeyWeave process, acting as the decentralized network.
    Uses IPFS to store encrypted shards.
    """
    def __init__(self):
        self.guardian_commitments = {}
        self.api_url = "http://127.0.0.1:5001"

    def add_to_ipfs(self, data: bytes) -> str:
        files = {'file': ('shard.txt', data)}
        response = requests.post(f"{self.api_url}/api/v0/add", files=files)
        response.raise_for_status()
        return response.json()["Hash"]

    def setup_escrow(self, secret, policy, guardians):
        """Splits and encrypts the secret, uploads to IPFS, and distributes CIDs."""
        print("\n--- Initiating KeyWeave Setup ---")
        if policy.num_guardians != len(guardians):
            raise ValueError("Policy must match the number of provided guardians.")

        shares = shamir_split_secret(secret, policy.threshold, policy.num_guardians)
        print(f"[KeyWeave] Secret split into {len(shares)} shares.")

        fernet = Fernet(FERNET_KEY)

        for i, guardian in enumerate(guardians):
            x, y = shares[i]
            shard_string = f"{x},{y}"
            encrypted = fernet.encrypt(shard_string.encode('utf-8'))

            cid = self.add_to_ipfs(encrypted)
            print(f"[IPFS] Uploaded shard for {guardian.name}, CID: {cid}")
            guardian.receive_shard_ipfs(cid, FERNET_KEY)

            self.guardian_commitments[guardian.did] = guardian.commitment

        print("[KeyWeave] All shares encrypted, uploaded to IPFS, and commitments recorded.")

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
