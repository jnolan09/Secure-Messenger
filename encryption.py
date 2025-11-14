"""
Encryption Module - AES-256-GCM and RSA-2048
Implements CONFIDENTIALITY (1 of 4 cryptography goals)

Extracted and refactored from reference/Server.py and Client.py
Originally implemented as networked client-server application

Standards Used:
- AES-256
- RSA-2048
- GCM Mode
- OAEP Padding
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class MessageEncryptor: 
    def __init__(self):
        # Dictionary storing RSA key pairs for each user
        self.user_keys = {}
    
    def generate_rsa_keys(self, username):
        # Generate RSA-2048 key pair
        private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
        public_key = private_key.public_key()
        
        self.user_keys[username] = {
            'private_key': private_key,
            'public_key': public_key}
    
    def generate_aes_key(self):
        # Generate random 256-bit AES key (new key each message)
        return os.urandom(32)
    
    def encrypt_message(self, plaintext, aes_key):
        """
        Encrypt message using AES-256 in GCM mode.
        GCM provides both encryption and authentication.
        """
        # Input validation
        if not plaintext:
            raise ValueError("Plaintext cannot be empty")
        if len(aes_key) != 32:
            raise ValueError("AES key must be 32 bytes")
        
        # Generate IV and encrypt with AES-GCM
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(aes_key),modes.GCM(iv),backend=default_backend()).encryptor() 
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        
         # Return all components needed for decryption
        return {
            'ciphertext': ciphertext,
            'iv': iv,
            'tag': encryptor.tag
        }
    
    def decrypt_message(self, encrypted_data, aes_key):
        # Decrypt and verify authentication tag
        try:
            ct = encrypted_data['ciphertext']
            iv = encrypted_data['iv']
            tag = encrypted_data['tag']
            
            cipher = Cipher(algorithms.AES(aes_key),modes.GCM(iv, tag),backend=default_backend())

            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ct) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
        
        except KeyError as e:
            raise ValueError(f"Invalid encrypted_data: missing {e}")
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def encrypt_aes_key(self, aes_key, recipient_public_key):
        # Encrypt AES key with recipient's RSA public key
        return recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    
    def decrypt_aes_key(self, encrypted_key, private_key):
        # Decrypt AES key with RSA private key
        try:
            return private_key.decrypt(
                encrypted_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        except Exception as e:
            raise ValueError(f"Key decryption failed: {e}")
    
    def get_public_key(self, username):
        # Retrieve public key for user
        if username not in self.user_keys:
            raise ValueError(f"No keys found for {username}")
        return self.user_keys[username]['public_key']
