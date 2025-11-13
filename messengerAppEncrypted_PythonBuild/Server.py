import socket  # For networking
import threading  # For multi-threading
import base64  # For encoding/decoding keys and messages
import os  # For random IV generation
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # For RSA
from cryptography.hazmat.primitives import serialization, hashes  # For cryptographic primitives
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # For AES-GCM
from cryptography.hazmat.backends import default_backend

PORT = 12345

# Generate RSA key pair (for the server)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()

aes_key = None  # Will be filled after handshake

# Helper: decrypt data with RSA private key
def rsa_decrypt(data):
    return private_key.decrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
    )

# Helper: decrypt AES-GCM message
def aes_gcm_decrypt(aes_key_bytes, iv, ciphertext):
    decryptor = Cipher(
        algorithms.AES(aes_key_bytes),
        modes.GCM(iv),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Helper: send encrypted message with AES-GCM
def send_encrypted(sock, key_bytes, plaintext):
    iv = os.urandom(12)  # Random 12-byte IV
    encryptor = Cipher(
        algorithms.AES(key_bytes),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    # send Base64(IV):Base64(ciphertext + tag)
    msg = base64.b64encode(iv).decode() + ':' + base64.b64encode(ciphertext + encryptor.tag).decode()
    sock.sendall(msg.encode() + b'\n')

# Accept incoming clients and handle handshake
def handle_client(client_sock):
    global aes_key

    # Step 1: Send RSA public key (Base64)
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    client_sock.sendall(base64.b64encode(pub_bytes) + b'\n')

    # Step 2: Receive encrypted AES key (Base64)
    encrypted_aes_key_b64 = client_sock.recv(4096).split(b'\n')[0]
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)

    # Step 3: Decrypt AES key
    aes_key = rsa_decrypt(encrypted_aes_key)

    print("Handshake complete. Waiting for messages...")

    # Start thread for incoming messages
    def reader():
        while True:
            line = client_sock.recv(4096)
            if not line:
                break
            line = line.decode().strip()
            parts = line.split(':')
            if len(parts) != 2:
                print("Malformed message")
                continue
            iv = base64.b64decode(parts[0])
            cipher_and_tag = base64.b64decode(parts[1])
            ct, tag = cipher_and_tag[:-16], cipher_and_tag[-16:]
            try:
                cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ct) + decryptor.finalize()
                message = plaintext.decode()
                print("Client:", message)
                if message.lower() == "bye":
                    break
            except Exception as e:
                print("Decryption error:", e)
                break
    threading.Thread(target=reader, daemon=True).start()

    # Main loop: read user input and send encrypted messages
    while True:
        message = input()
        if not aes_key:
            print("AES key missing")
            continue
        send_encrypted(client_sock, aes_key, message)
        if message.lower() == "bye":
            break

    client_sock.close()

def main():
    # Set up server socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', PORT))
        s.listen(1)
        print(f"Server listening on port {PORT}")
        conn, addr = s.accept()
        print(f"Client connected from {addr}")
        handle_client(conn)
        print("Server closed.")

if __name__ == '__main__':
    main()
