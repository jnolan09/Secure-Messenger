"""
Eel Application - Desktop UI Backend
Integration layer connecting encryption.py and verification.py

Demonstrates all 4 cryptography goals:
1. Confidentiality - AES-256-GCM encryption (encryption.py)
2. Integrity - SHA-256 hashing (verification.py)
3. Authentication - RSA-PSS signatures (verification.py)
4. Non-Repudiation - Cryptographic logging (verification.py)
"""

import eel
import datetime
from encryption import MessageEncryptor
from verification import MessageVerifier

# Initialize modules
encryptor = MessageEncryptor()
verifier = MessageVerifier()
messages = []

# Initialize Eel with web folder
eel.init('web')

@eel.expose
def generate_keys(username, recipient):
    """
    Generate RSA-2048 key pairs for both users.
    Required before any encrypted communication.
    """
    try:
        # Generate separate key pairs for each user
        encryptor.generate_rsa_keys(username)
        encryptor.generate_rsa_keys(recipient)
        return {
            'success': True,
            'message': f'Keys generated for {username} and {recipient}'
        }
    except Exception as e:
        return {
            'success': False,
            'message': str(e)
        }
    
@eel.expose
def send_message(sender, recipient, message_text):
    """
    Encrypt, sign, and log a message.
    Implements all 4 cryptography goals in one operation.
    
    Process:
    1. Generate new AES key (forward secrecy)
    2. Encrypt message (confidentiality)
    3. Hash ciphertext (integrity)
    4. Sign hash (authentication)
    5. Encrypt AES key for recipient (secure key exchange)
    6. Log everything (non-repudiation)
    """
    try:
        # Generate new AES key and encrypt message
        aes_key = encryptor.generate_aes_key()
        encrypted_data = encryptor.encrypt_message(message_text, aes_key)

        # Create hash and signature
        message_hash = verifier.create_hash(encrypted_data['ciphertext'])
        sender_private_key = encryptor.user_keys[sender]['private_key']
        signature = verifier.create_signature(message_hash, sender_private_key)

        # Encrypt AES key for recipient
        recipient_public_key = encryptor.get_public_key(recipient)
        encrypted_aes_key = encryptor.encrypt_aes_key(aes_key, recipient_public_key)

        # Log the message
        timestamp = datetime.datetime.now().isoformat()
        verifier.log_message(sender, recipient, message_hash, signature, timestamp)

        # Store message as package
        message_package = {
            'sender': sender,
            'recipient': recipient,
            'encrypted_data': encrypted_data, # Ciphertext + IV + tag
            'encrypted_aes_key': encrypted_aes_key, # RSA-encrypted key
            'message_hash': message_hash, # SHA-256 hash
            'signature': signature,  # RSA-PSS signature
            'timestamp': timestamp,
            'original_message': message_text
        }
        messages.append(message_package)

        return {
            'success': True,
            'message': message_text,
            'timestamp': timestamp
        }
    except Exception as e:
        return {
            'success': False,
            'message': str(e)
        }
    
@eel.expose
def receive_message():
    """
    Decrypt and verify the last message.
    Verifies signature and hash before decryption.
    
    Process:
    1. Decrypt AES key using recipient's private key
    2. Verify signature (authentication check)
    3. Verify hash (integrity check)
    4. Decrypt message (only if verification passes)
    """
    # Check if any messages exist
    if not messages:
        return {
            'success': False,
            'message': 'No messages to receive'
        }
    
    try:
       package = messages[-1]
       recipient = package['recipient']

       # Decrypt AES key 
       recipient_private_key = encryptor.user_keys[recipient]['private_key']
       aes_key = encryptor.decrypt_aes_key(package['encrypted_aes_key'], recipient_private_key)

       # Verify signature 
       sender_public_key = encryptor.get_public_key(package['sender'])
       is_authentic = verifier.verify_signature(
           package['message_hash'],
           package['signature'],
           sender_public_key
       )

       if not is_authentic:
           return {
               'success': False,
               'message': 'Invalid signature'
           }
       
       # Verify hash
       is_intact = verifier.verify_hash(
           package['encrypted_data']['ciphertext'],
           package['message_hash']
       )

       if not is_intact:
           return {
               'success': False,
               'message': 'Hash verification failed'
           }
       
       # Decrypt message
       decrypted = encryptor.decrypt_message(package['encrypted_data'], aes_key)

       return {
           'success': True,
           'sender': package['sender'],
           'message': decrypted,
           'timestamp': package['timestamp']
       }
    except Exception as e:
        return {
            'success': False,
            'message': str(e)
        }

@eel.expose
def get_logs():
    # Get all message logs
    logs = verifier.get_logs()
    return logs

@eel.expose
def clear_history():
    # Clear message history
    global messages
    messages = []
    return {'success': True}

# Start application
if __name__ == '__main__':
    eel.start('index.html', size=(1000,720))