/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package encryptedmessageapp;

/**
 *
 * @author seang
 */
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Server {

    // Port number to listen on
    private static final int PORT = 12345;

    // RSA keypair (public/private) for this server
    private KeyPair rsaKeyPair;

    // AES session key (shared with client after handshake)
    private SecretKey aesKey;

    // Constructor: generate a new RSA key pair when the server starts
    public Server() throws Exception {
        rsaKeyPair = generateRSAKeyPair();
    }

    // Start the server and handle communication
    public void start() throws Exception {
        // Create a server socket to listen for incoming connections
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Secure server listening on port " + PORT);

        // Wait for a client to connect (this blocks until someone connects)
        Socket clientSocket = serverSocket.accept();
        System.out.println("Client connected from " + clientSocket.getInetAddress());

        // Input and output streams for network communication
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

        // Read messages from the server console
        BufferedReader console = new BufferedReader(new InputStreamReader(System.in));

        // --- HANDSHAKE PHASE ---

        // Step 1: Send server's RSA public key to the client (Base64 encoded)
        String serverPubBase64 = Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded());
        out.println(serverPubBase64);
        System.out.println("Sent server RSA public key to client.");

        // Step 2: Receive AES key encrypted with server's RSA public key
        String encryptedAesKeyBase64 = in.readLine();
        if (encryptedAesKeyBase64 == null) {
            throw new IOException("Client closed before sending AES key.");
        }

        // Decode from Base64 into byte array
        byte[] encryptedAesKey = Base64.getDecoder().decode(encryptedAesKeyBase64);

        // Step 3: Decrypt AES key using server's RSA private key
        byte[] aesKeyBytes = rsaDecrypt(encryptedAesKey, rsaKeyPair.getPrivate());

        // Convert raw bytes into a usable SecretKey object
        aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        System.out.println("Received and decrypted AES session key. Chat ready.");

        // --- MESSAGE EXCHANGE PHASE ---

        // Create a new thread to continuously read and decrypt incoming messages
        Thread reader = new Thread(() -> {
            try {
                String line;
                while ((line = in.readLine()) != null) {
                    // Each incoming line is in format: IV_BASE64:CIPHERTEXT_BASE64
                    String[] parts = line.split(":");

                    // Basic check to ensure format is correct
                    if (parts.length != 2) {
                        System.out.println("Malformed message received.");
                        continue;
                    }

                    // Decode IV and ciphertext from Base64
                    byte[] iv = Base64.getDecoder().decode(parts[0]);
                    byte[] cipherBytes = Base64.getDecoder().decode(parts[1]);

                    // Decrypt ciphertext using AES-GCM
                    String plaintext = aesGcmDecrypt(aesKey, iv, cipherBytes);

                    // If client says "bye", end chat
                    if (plaintext.equalsIgnoreCase("bye")) {
                        System.out.println("Client ended the chat.");
                        break;
                    }

                    // Display decrypted message
                    System.out.println("Client: " + plaintext);
                }
            } catch (Exception e) {
                System.out.println("Reader error: " + e.getMessage());
            }
        });

        // Start the background reader thread
        reader.start();

        // Main thread: read user input from console and send encrypted messages
        try {
            String message;
            while ((message = console.readLine()) != null) {

                // Ignore until AES key is set (just safety)
                if (aesKey == null) {
                    System.out.println("AES key not established yet.");
                    continue;
                }

                // If user types "bye", send and exit
                if (message.equalsIgnoreCase("bye")) {
                    sendEncrypted(out, aesKey, message);
                    break;
                }

                // Encrypt and send normal messages
                sendEncrypted(out, aesKey, message);
            }
        } finally {
            // Cleanly close sockets and stop server
            clientSocket.close();
            serverSocket.close();
            System.out.println("Server closed.");
        }
    }

    // Helper method to encrypt a message with AES-GCM and send over the network
    private static void sendEncrypted(PrintWriter out, SecretKey aesKey, String plaintext) throws Exception {
        // Generate random 12-byte IV (unique per message)
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Encrypt the plaintext with AES-GCM
        byte[] cipherBytes = aesGcmEncrypt(aesKey, iv, plaintext);

        // Combine and send as Base64(iv):Base64(ciphertext)
        String outLine = Base64.getEncoder().encodeToString(iv) + ":" +
                         Base64.getEncoder().encodeToString(cipherBytes);
        out.println(outLine);
    }

    // Generate a fresh RSA key pair (2048-bit)
    private static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    // Decrypt data with RSA private key (OAEP padding for security)
    private static byte[] rsaDecrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        return rsa.doFinal(data);
    }

    // Encrypt plaintext with AES in GCM mode
    private static byte[] aesGcmEncrypt(SecretKey key, byte[] iv, String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128-bit authentication tag
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(plaintext.getBytes("UTF-8"));
    }

    // Decrypt ciphertext with AES-GCM
    private static String aesGcmDecrypt(SecretKey key, byte[] iv, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] plain = cipher.doFinal(ciphertext);
        return new String(plain, "UTF-8");
    }

    // Program entry point
    public static void main(String[] args) {
        try {
            // Create and start the secure server
            Server server = new Server();
            server.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
