# verification.py
# Handles Integrity, Authtentication and Non-Repudation
# Joshua Nolan

import hashlib
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
from cryptography.exceptions import InvalidSignature

# Security configuration constraints
HASH_ALGORITHM = "SHA-256"
SIGNATURE_KEY_SIZE = 2048
SIGNATURE_ALGORITHM = "RSA"
PADDING_SCENE = "PSS"
MAX_MESSAGE_AGE_MINUTES = 60

class MessageVerifier:
    """
    This class handles message verification for secure messenging.

    Implements 3 of the 4 cryptography goals:
    1. Integrity: Detects message tampering using SHA-256 hashing
    2. Authentication: Verifies sender identity using digital signature
    3. Non-Repudation: Maintains permanent logs of all messages
    """

    def __init__(self):
        # Store all message logs
        self.message_log = []
        print("="*30)
        print("MESSAGE VERIFIER")
        print("="*30)
        print(f"Hash Algorithm: {HASH_ALGORITHM}")
        print(f"Signature Algorithm: {SIGNATURE_ALGORITHM}-{SIGNATURE_KEY_SIZE}")
        print(f"Padding Scheme: {PADDING_SCENE}")
        print("="*30 + "\n")

    # Integrity Functions
    def create_hash(self, data):
        """
        Create a SHA-256 hash of data
        
        This detects if anyone tampers with the date during transmission
        """
        try:
            # Handle both string and bytes input
            if isinstance(data,str):
                data_bytes = data.encode('utf-8')
            elif isinstance(data, bytes):                    
                data_bytes = data
            else:
                raise ValueError("Data must be string or bytes")
                
            # Create SHA-256 hash object
            hash_object = hashlib.sha256(data_bytes)

            # Get the hash as a readable hex string 
            hash_hex = hash_object.hexdigest()

            print (f"Hash CREATED using {HASH_ALGORITHM} (input: {len(data_bytes)}  bytes)")
            return hash_hex
                
        except Exception as e:
            print(f"ERROR creating hash: {e}")
            return None
            
        
# Test
if __name__ == "__main__":
    verifier = MessageVerifier()
    test_hash = verifier.create_hash("Hello World")
    print(f"Test Hash: {test_hash}")