package com;

import java.io.IOException;
import java.net.ServerSocket;

public class BobMultiserver {

	public static void main(String[] args) {
		
		// Port number for Bob
		int portNumber = 4444;
        boolean listening = true;
        
        // Accept multiple client requests
        try (ServerSocket serverSocket = new ServerSocket(portNumber)) { 
            while (listening) {
                new Bob(serverSocket.accept()).start();
            }
        } catch (IOException e) {
            System.err.println("Could not listen on port " + portNumber);
        }

	}

}
