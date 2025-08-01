import random

# A large prime number for our finite field arithmetic in Shamir's Secret Sharing
# In a real system, this would be much larger and chosen carefully.
PRIME = 2**127 - 1

def shamir_split_secret(secret, threshold, num_shares):
    """
    Splits a secret into a number of shares using Shamir's Secret Sharing.
    """
    if threshold > num_shares:
        raise ValueError("Threshold cannot be greater than the number of shares.")

    coeffs = [secret] + [random.randint(1, PRIME - 1) for _ in range(threshold - 1)]

    def evaluate_poly(x):
        y = 0
        for coeff in reversed(coeffs):
            y = (y * x + coeff) % PRIME
        return y

    shares = []
    for i in range(1, num_shares + 1):
        x = i
        y = evaluate_poly(x)
        shares.append((x, y))
        
    return shares

def shamir_reconstruct_secret(shares):
    """
    Reconstructs the secret from a list of shares using Lagrange Interpolation.
    """
    if not shares:
        raise ValueError("Cannot reconstruct secret from zero shares.")
    
    secret = 0
    for j, (xj, yj) in enumerate(shares):
        numerator = 1
        denominator = 1
        for m, (xm, _) in enumerate(shares):
            if m != j:
                numerator = (numerator * -xm) % PRIME
                denominator = (denominator * (xj - xm)) % PRIME
        
        lagrange_poly = (numerator * pow(denominator, -1, PRIME)) % PRIME
        term = (yj * lagrange_poly) % PRIME
        secret = (secret + term) % PRIME
        
    return secret
