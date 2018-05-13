package com;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;

public class KDC {

	// Shared key between Bob and KDC used to generate two keys for 3DES
	private static String sharedkey_BobKDC = Constants.K_BOB_KDC;
	// Shared key between Alice and KDC used to generate two keys for 3DES
	private static String sharedkey_AliceKDC = Constants.K_ALICE_KDC;

	public static void main(String[] args) {

		// Server socket for KDC
		ServerSocket firstsocket = null;
		Socket serversocket = null;

		try {
			firstsocket = new ServerSocket(5555);
		} catch (IOException e) {
			e.printStackTrace();
		}

		try {

			// Socket to communicate with Alice
			serversocket = firstsocket.accept();
			PrintWriter out = new PrintWriter(serversocket.getOutputStream(),
					true);
			BufferedReader in = new BufferedReader(new InputStreamReader(
					serversocket.getInputStream()));

			// Receive message 3 from Alice to KDC - N1, Alice wants Bob,
			// K_Bob{Nb}
			String inputline = null;
			while ((inputline = in.readLine()) != null) {
				break;
			}
			System.out.println("Read message 3 from Alice to KDC");

			// N1 from message 3
			String N1 = inputline.substring(0, 64);
			// 'Alice' from message 3
			int from = Integer.parseInt(inputline.substring(64, 65));
			// ' Bob' from message 3
			int to = Integer.parseInt(inputline.substring(65, 66));
			String toBeDecrypted = inputline.substring(66, inputline.length());

			String decrypted = null;
			String encryptedTicket = null;
			String Kab = null;
			if (to == 2) {

				// Decrypt Nb from message 3
				TripleDES td = new TripleDES(sharedkey_BobKDC);
				decrypted = td.decrypt(toBeDecrypted);
				;

				// Generate key Kab
				SecureRandom random = new SecureRandom();
				long val = random.nextLong();
				long val1 = random.nextLong();
				Kab = String.valueOf(val).concat(String.valueOf(val1));

				// Create ticket to Bob, encrpted with K_Bob
				String ticketToBob = (Kab).concat(String.valueOf(from)).concat(
						decrypted);
				encryptedTicket = (td.encrypt(ticketToBob));
			}

			String encryptedToAlice = null;
			if (from == 1) {

				// Encrypt message to Alice with K_Alice
				String sendToAlice = N1.concat(String.valueOf(to))
						.concat(String.valueOf(Kab.length())).concat(Kab)
						.concat(encryptedTicket);
				TripleDES td = new TripleDES(sharedkey_AliceKDC);
				encryptedToAlice = td.encrypt(sendToAlice);
			}

			// Send message 4 to Alice - K_Alice{N1, Bob, Kab, ticket
			// to Bob}
			out.println(encryptedToAlice);
			System.out.println("Sent message 4 from KDC to Alice");

			// End all communication with Alice
			out.close();
			in.close();
			serversocket.close();
			firstsocket.close();

		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
}
