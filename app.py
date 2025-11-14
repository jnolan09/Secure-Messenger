"""
Eel Application - Desktop UI Backend
Uses encryption.py and verification.py
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
    # Generate RSA keys for both users
    try:
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
    #Encrypt and sign message
    try:
        # Generate AES ket and encrypt message
        aes_key = encryptor.generate_aes_key()
        encrypted_data = encryptor.encrypt_message(message_text, aes_key)

        # Create hash and signature
        message_hash = verifier.create_hash(encrypted_data['ciphertext'])
        sender_private_key = encryptor.user_keys[sender]['private_key']
        signature = verifier.create_signature(message_hash, sender_private_key)

        # Encrypt AES key for recipient
        recipient_public_key = encryptor.get_public_key(recipient)
        encrypted_aes_key = encryptor.encrypt_aes_key(aes_key, recipient_public_key)

        # Log the messsage
        timestamp = datetime.datetime.now().isoformat()
        verifier.log_message(sender, recipient, message_hash, signature, timestamp)

        # Store message as package
        message_package = {
            'sender': sender,
            'recipient': recipient,
            'encrypted_data': encrypted_data,
            'encrypted_aes_key': encrypted_aes_key,
            'message_hash': message_hash,
            'signature': signature,
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
    # Decrypt and verify last message
    if not messages:
        return {
            'success': False,
            'message': 'No messages to recieve'
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
def ger_logs():
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