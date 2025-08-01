from .crypto import shamir_split_secret, shamir_reconstruct_secret

class KeyWeaveNetwork:
    """
    Orchestrates the KeyWeave process, acting as the decentralized network.
    """
    def __init__(self):
        self.guardian_commitments = {}

    def setup_escrow(self, secret, policy, guardians):
        """Sets up the secret escrow by splitting the secret and distributing shards."""
        print("\n--- Initiating KeyWeave Setup ---")
        if policy.num_guardians != len(guardians):
            raise ValueError("Policy must match the number of provided guardians.")
            
        shares = shamir_split_secret(secret, policy.threshold, policy.num_guardians)
        print(f"[KeyWeave] Secret split into {len(shares)} shares.")

        for i, guardian in enumerate(guardians):
            guardian.receive_shard(shares[i])
            self.guardian_commitments[guardian.did] = guardian.commitment
        print("[KeyWeave] All shares distributed and commitments recorded.")

    def initiate_recovery(self, recovery_guardians, policy):
        """Initiates the recovery process."""
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
