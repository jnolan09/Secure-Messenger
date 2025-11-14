/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package messengerappbase;

/**
 *
 * @author seang
 */
import java.io.*;
import java.net.*;

public class Client {
    public static void main(String[] args) {
        String host = "localhost";
        int port = 1234;

        try (Socket socket = new Socket(host, port)) {
            System.out.println("Connected to server!");

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader console = new BufferedReader(new InputStreamReader(System.in));

            String inputLine, outputLine;
            while (true) {
                System.out.print("You: ");
                outputLine = console.readLine();
                out.println(outputLine);
                if (outputLine.equalsIgnoreCase("bye")) break;

                inputLine = in.readLine();
                System.out.println("Server: " + inputLine);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}