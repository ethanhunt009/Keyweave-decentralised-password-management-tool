import unittest
from shamir import ShamirSecretSharing
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import config

class SecurityAudit(unittest.TestCase):
    def test_shamir_correctness(self):
        """Verify secret can be reconstructed from sufficient shares"""
        secret = os.urandom(config.Config.SECRET_LENGTH)
        shamir = ShamirSecretSharing(threshold=3, total_shares=5)
        shares = shamir.split_secret(secret)
        
        # Test reconstruction with minimum shares
        reconstructed = shamir.recover_secret(shares[:3])
        self.assertEqual(secret, reconstructed)
        
        # Test reconstruction with extra shares
        reconstructed = shamir.recover_secret(shares)
        self.assertEqual(secret, reconstructed)
    
    def test_shamir_insufficient_shares(self):
        """Verify insufficient shares fail reconstruction"""
        secret = os.urandom(config.Config.SECRET_LENGTH)
        shamir = ShamirSecretSharing(threshold=3, total_shares=5)
        shares = shamir.split_secret(secret)
        
        with self.assertRaises(ValueError):
            shamir.recover_secret(shares[:2])
    
    def test_commitment_verification(self):
        """Test cryptographic commitment system"""
        secret1 = os.urandom(config.Config.SECRET_LENGTH)
        secret2 = os.urandom(config.Config.SECRET_LENGTH)
        
        # Create commitment
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(secret1)
        commitment = digest.finalize()
        
        # Verify correct secret
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(secret1)
        self.assertEqual(digest.finalize(), commitment)
        
        # Verify different secret
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(secret2)
        self.assertNotEqual(digest.finalize(), commitment)
    
    def test_zk_proof_simulation(self):
        """Test simulated zero-knowledge proof system"""
        from guardian.zk_protocols import ZKProofSystem
        
        secret = os.urandom(config.Config.SECRET_LENGTH)
        challenge = os.urandom(config.Config.ZK_CHALLENGE_SIZE)
        zk = ZKProofSystem()
        
        # Generate proof
        proof = zk.generate_proof(secret, challenge)
        
        # Verify valid proof
        self.assertTrue(zk.verify_proof(proof, secret, challenge))
        
        # Verify invalid proof
        self.assertFalse(zk.verify_proof(b"invalid", secret, challenge))
        self.assertFalse(zk.verify_proof(proof, b"wrong-secret", challenge))
        self.assertFalse(zk.verify_proof(proof, secret, b"wrong-challenge"))

if __name__ == '__main__':
    unittest.main()