from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import config

def generate_secret(length=config.Config.SECRET_LENGTH):
    """Generate cryptographically secure random secret"""
    return os.urandom(length)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=config.Config.KDF_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_secret(secret: bytes, key: bytes) -> bytes:
    """Encrypt secret using AES-256-CBC"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
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
    
    unpadder = padding.PKCS7(128).unpadder()
    secret = unpadder.update(padded_data) + unpadder.finalize()
    
    return secret

def create_commitment(data: bytes) -> str:
    """Create cryptographic commitment"""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize().hex()