"""
Cryptography module for end-to-end encrypted chat.
Provides AES-EAX encryption with SHA-256 key derivation.
"""

import hashlib
from Crypto.Cipher import AES


def get_key(password: str) -> bytes:
    """
    Derive a 256-bit AES key from a password using SHA-256.
    
    Args:
        password: The shared password string
        
    Returns:
        32-byte (256-bit) AES key
    """
    return hashlib.sha256(password.encode('utf-8')).digest()


def encrypt(message: str, key: bytes) -> bytes:
    """
    Encrypt a plaintext message using AES-EAX mode.
    
    Args:
        message: The plaintext message to encrypt
        key: 256-bit AES key
        
    Returns:
        Encrypted message as bytes: nonce + tag + ciphertext
    """
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return cipher.nonce + tag + ciphertext


def decrypt(cipher_bytes: bytes, key: bytes) -> str:
    """
    Decrypt a ciphertext message using AES-EAX mode.
    Verifies message integrity using the authentication tag.
    
    Args:
        cipher_bytes: Encrypted message (nonce + tag + ciphertext)
        key: 256-bit AES key
        
    Returns:
        Decrypted plaintext message
        
    Raises:
        ValueError: If message authentication fails (tampered message)
    """
    nonce = cipher_bytes[:16]
    tag = cipher_bytes[16:32]
    ciphertext = cipher_bytes[32:]
    
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    return plaintext.decode('utf-8')
