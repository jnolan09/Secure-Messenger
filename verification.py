# verification.py
# Handles Integrity, Authentication and Non-Repudiation
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
PADDING_SCHEME = "PSS"
MAX_MESSAGE_AGE_MINUTES = 60

class MessageVerifier:
    """
    This class handles message verification for secure messenging.

    Implements 3 of the 4 cryptography goals:
    1. Integrity: Detects message tampering using SHA-256 hashing
    2. Authentication: Verifies sender identity using digital signature
    3. Non-Repudiation: Maintains permanent logs of all messages
    """

    def __init__(self):
        # Store all message logs
        self.message_log = []
        print("="*30)
        print("MESSAGE VERIFIER")
        print("="*30)
        print(f"Hash Algorithm: {HASH_ALGORITHM}")
        print(f"Signature Algorithm: {SIGNATURE_ALGORITHM}-{SIGNATURE_KEY_SIZE}")
        print(f"Padding Scheme: {PADDING_SCHEME}")
        print("="*30 + "\n")

    # Integrity Functions
    def create_hash(self, data):
        """
        Create a SHA-256 hash of data
        
        This detects if anyone tampers with the data during transmission
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
            
    def verify_hash(self, data, received_hash):
        """  
        Verify if data's hash matches the expected hash.
        """
        # Validate inputs
        if not data:
            print("ERROR: Data is empty")
            return False
        
        if not received_hash or len(received_hash) != 64:
            print(f"ERROR: Invalid hash format (Expected: 64, received {len(received_hash) if received_hash else 0})")
            return False            
        
        try:
            # Calculate the hash of the data we received
            calculated_hash = self.create_hash(data)
            if calculated_hash is None:
                return False
            
            # Compare with the hash we were told to expect
            if calculated_hash == received_hash:
                print("Integrity check PASSED: Data is intact")
                return True
            else:
                print("Integrity check FAILED: Data was tampered with")
                print(f"Expected: {received_hash[:32]}...")
                print(f"Got: {calculated_hash[:32]}...")
                return False
            
        except Exception as e:
            print(f"ERROR verifying hash: {e}")
            return False
        
    # Authentication functions 
    def create_signature(self, message_hash, private_key):
        """
        Create a digital signature by signing the message hash with the sender's private key
        """
        try:
            if not message_hash or len(message_hash) != 64:
                raise ValueError("Invalid message hash")
            
            # Convert hash string to bytes
            hash_bytes = message_hash.encode('utf-8')

            # Sign the hash with the private key using PSS padding
            signature = private_key.sign(
                hash_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            print(f"Digital signature created using {SIGNATURE_ALGORITHM}-{SIGNATURE_KEY_SIZE}")
            return signature
        
        except Exception as e:
            print(f"ERROR creating signature: {e}")
            return None
        
    def verify_signature(self, message_hash, signature, public_key):
        """
        Verify a digital signature using the sender's public key
        """
        try:
            if not message_hash or len(message_hash) != 64:
                print("ERROR: Invalid message hash format")
                return False
            
            if not signature:
                print("ERROR: Signature is empty")
                return False
            
            # Convert hash to bytes 
            hash_bytes = message_hash.encode('utf-8')

            # Try to verify the signature
            public_key.verify(
                signature,
                hash_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            print("Authentication PASSED: Signature is valid")
            print("Sender identity verified using RSA public key")
            return True
        
        except InvalidSignature:
            print("Authentication FAILED: Invalid signature")
            print("This message may be fake or tampered with")
            return False
        except Exception as e:
            print(f"ERROR verifying signature: {e}")
            return False
        
    # Non-Repudiation functions
    def log_message(self, sender, recipient, message_hash, signature, timestamp):
        """
        Log a message with its signature and timestamp

        The sender can't later deny that they sent this message because we have proof
        """
        try:
            log_entry = {
                'sender': sender,
                'recipient': recipient,
                'message_hash': message_hash,
                'signature': signature.hex(),
                'timestamp': timestamp,
                'logged_at': datetime.datetime.now().isoformat(),
                'hash_algorithm': HASH_ALGORITHM,
                'signature_algorithm': f"{SIGNATURE_ALGORITHM}-{SIGNATURE_KEY_SIZE}"
            }

            # Add to permanent log
            self.message_log.append(log_entry)

            print(f"Non-Repudiation: Message Logged")
            print(f"From: {sender} To: {recipient}")
            print(f"Timestamp: {timestamp}")
            print(f"Log Entry #{len(self.message_log)}")

        except Exception as e:
            print(f"ERROR logging message: {e}")

    def get_logs(self):
        """
        Retrieve all logged messages
        """
        return self.message_log
    
    def display_logs(self):
        """
        Display all logged messages in a readable format
        """
        if not self.message_log:
            print("\n" + "="*30)
            print("No messages logged")
            print("="*30 + "\n")
            return
        
        print("\n" + "="*30)
        print("Message Log")
        print("="*30)
        print(f"Total Messages: {len(self.message_log)}")
        print("="*30)

        for i, log in enumerate(self.message_log, 1):
            print(f"\nMessage #{i}:")
            print(f"From: {log['sender']}")
            print(f"To: {log['recipient']}")
            print(f"Sent: {log['timestamp']}")
            print(f"Logged: {log['logged_at']}")
            print(f"Hash: {log['message_hash'][:32]}")
            print(f"Signature: {log['signature'][:32]}")

        print ("\n" + "="*30 + "\n")
        
# Test
if __name__ == "__main__":
    verifier = MessageVerifier()

    # Test 1: Hash creation
    print("\nTest 1: Create Hash")
    message = "Hello World"
    test_hash = verifier.create_hash(message)
    print(f"Hash: {test_hash}\n")

    # Test 2: Hash verification (intact)
    print("Test 2: Verify Intact Message")
    verifier.verify_hash(message, test_hash)

    # Test 3: Hash verification (tampered)
    print("\nTest 3: Detect Tampered Message")
    verifier.verify_hash("Hello World!", test_hash)

    # Test 4: Digital signatures
    print("\nTest 4: Digital Signatures")
    print("Generating RSA keys")

    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    # Generate test keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    print("Keys generated\n")

    # Create signature
    print("Creating signature")
    signature = verifier.create_signature(test_hash, private_key)

    # Verify signature
    print("\nVerifying signature")
    verifier.verify_signature(test_hash, signature, public_key)

    print("\n" + "="*30)
    print("All tests complete")
    print("="*30)

    # Test 5: Non-Repudiation - Logging
    print("\nTest 5: Non-Repudiation - Message Logging")
    verifier.log_message(
        sender= "John",
        recipient= "Alex",
        message_hash= test_hash,
        signature= signature,
        timestamp= datetime.datetime.now().isoformat()
    )

    # Display Logs
    print("\nDisplaying message logs:")
    verifier.display_logs()
