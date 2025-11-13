import socket  # For networking
import threading  # For multi-threading
import base64  # For encoding/decoding
import os  # For random IV generation
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = "localhost"
PORT = 12345

# Helper: encrypt AES key with RSA public key
def rsa_encrypt(data, pubkey):
    return pubkey.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
    )

# Helper: encrypt plaintext using AES-GCM
def aes_gcm_encrypt(aes_key_bytes, plaintext):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(aes_key_bytes),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    return iv, ciphertext + encryptor.tag

# Helper: decrypt AES-GCM
def aes_gcm_decrypt(aes_key_bytes, iv, ct_and_tag):
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    cipher = Cipher(algorithms.AES(aes_key_bytes), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def main():
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        # Step 1: Receive server's RSA public key (Base64)
        pub_b64 = sock.recv(4096).split(b'\n')[0]
        pub_bytes = base64.b64decode(pub_b64)
        server_pubkey = serialization.load_der_public_key(pub_bytes, backend=default_backend())

        # Step 2: Generate AES key
        aes_key_bytes = os.urandom(32)  # 256-bit

        # Step 3: Encrypt AES key with server's public key
        encrypted_aes = rsa_encrypt(aes_key_bytes, server_pubkey)

        # Step 4: Send encrypted AES key (Base64)
        sock.sendall(base64.b64encode(encrypted_aes) + b'\n')

        print("Handshake complete. Ready to chat.")

        # Start thread for incoming messages
        def reader():
            while True:
                line = sock.recv(4096)
                if not line:
                    break
                line = line.decode().strip()
                parts = line.split(':')
                if len(parts) != 2:
                    print("Malformed message")
                    continue
                iv = base64.b64decode(parts[0])
                cipher_and_tag = base64.b64decode(parts[1])
                try:
                    decrypted = aes_gcm_decrypt(aes_key_bytes, iv, cipher_and_tag)
                    message = decrypted.decode()
                    print("Server:", message)
                    if message.lower() == "bye":
                        break
                except Exception as e:
                    print("Decryption error:", e)
                    break
        threading.Thread(target=reader, daemon=True).start()

        # Main loop: read input and send encrypted messages
        while True:
            msg = input()
            iv, cipher_and_tag = aes_gcm_encrypt(aes_key_bytes, msg)
            out_line = base64.b64encode(iv).decode() + ':' + base64.b64encode(cipher_and_tag).decode()
            sock.sendall(out_line.encode() + b'\n')
            if msg.lower() == "bye":
                break

if __name__ == '__main__':
    main()