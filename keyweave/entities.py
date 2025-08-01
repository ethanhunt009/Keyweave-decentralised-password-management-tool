import uuid
import hashlib

class Guardian:
    """
    Represents a Guardian in the KeyWeave network.
    """
    def __init__(self, name):
        self.name = name
        # SIMULATION: Decentralized Identifier (DID)
        self.did = f"did:example:{uuid.uuid4()}"
        self.shard = None
        self.commitment = None

    def receive_shard(self, shard):
        """Receives a secret shard and creates a public commitment to it."""
        self.shard = shard
        # SIMULATION: Zero-Knowledge Proof Commitment
        shard_string = f"{self.shard[0]},{self.shard[1]}"
        self.commitment = hashlib.sha256(shard_string.encode()).hexdigest()
        print(f"  [Guardian {self.name}] Received shard. Public commitment is: {self.commitment[:10]}...")

    def provide_proof(self):
        """SIMULATION of a Guardian providing a Zero-Knowledge Proof."""
        print(f"  [Guardian {self.name}] Providing proof of shard knowledge.")
        return {"did": self.did, "commitment": self.commitment}
        
    def provide_shard_for_reconstruction(self):
        """Called ONLY after enough valid proofs have been provided."""
        print(f"  [Guardian {self.name}] Proof accepted. Providing shard for reconstruction.")
        return self.shard

class RecoveryPolicy:
    """
    Represents a user's recovery policy, like a Verifiable Credential.
    """
    def __init__(self, threshold, guardian_dids):
        self.threshold = threshold
        self.num_guardians = len(guardian_dids)
        self.authorized_dids = set(guardian_dids)
        print(f"[Policy Created] Recovery requires {self.threshold} of {self.num_guardians} specific guardians.")
