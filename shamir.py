import random
import config

class ShamirSecretSharing:
    """Implementation of Shamir's Secret Sharing scheme"""
    
    def __init__(self, threshold: int, total_shares: int):
        self.threshold = threshold
        self.total_shares = total_shares
        self.prime = config.Config.SHAMIR_PRIME
    
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
        if secret_int >= self.prime:
            raise ValueError("Secret is too large for the chosen prime")
        
        # Generate random coefficients
        coefficients = [secret_int] + [
            random.randint(1, self.prime-1) 
            for _ in range(self.threshold-1)
        ]
        
        # Generate shares
        shares = []
        for i in range(1, self.total_shares + 1):
            x = i
            y = self._evaluate_polynomial(coefficients, x, self.prime)
            shares.append(y.to_bytes(32, 'big'))  # Fixed size for research
        
        return shares
    
    def recover_secret(self, shares: list) -> bytes:
        """Recover secret from shares using Lagrange interpolation"""
        if len(shares) < self.threshold:
            raise ValueError(f"Not enough shares. Need {self.threshold}, got {len(shares)}")
        
        # Convert shares to integers
        points = [(i+1, int.from_bytes(share, 'big')) for i, share in enumerate(shares)]
        
        secret_int = 0
        for j in range(len(points)):
            x_j, y_j = points[j]
            
            # Lagrange basis polynomial
            basis = 1
            for m in range(len(points)):
                if m == j:
                    continue
                x_m, y_m = points[m]
                denom = (x_j - x_m) % self.prime
                inv_denom = pow(denom, -1, self.prime)  # Modular inverse
                basis = (basis * (-x_m) * inv_denom) % self.prime
            
            secret_int = (secret_int + y_j * basis) % self.prime
        
        # Convert integer back to bytes
        return secret_int.to_bytes(32, 'big')