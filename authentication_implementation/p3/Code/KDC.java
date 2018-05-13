package com;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Random;

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

			// Receive message 1 from Alice to KDC - N1, Alice wants Bob
			String inputline = null;
			while ((inputline = in.readLine()) != null) {
				break;
			}
			System.out.println("Read message 1 from Alice to KDC");

			// N1 from message 1
			String N1 = inputline.substring(0, 64);
			// 'Alice' from message 1
			int from = Integer.parseInt(inputline.substring(64, 65));
			// 'Bob' from message 1
			int to = Integer.parseInt(inputline.substring(65, 66));

			String encryptedTicket = null;
			String Kab = null;

			// Check if receiver will be 'Bob'
			if (to == 2) {

				// To encrypt ticket to Bob
				Encrypter td = new Encrypter(sharedkey_BobKDC,
						Constants.CBC_ALGORITHM_WITH_PADDING);

				// Generate key Kab
				SecureRandom random = new SecureRandom();
				long val = random.nextLong();
				long val1 = random.nextLong();
				Kab = String.valueOf(val).concat(String.valueOf(val1));

				// Generate ticket to Bob - {Kab, 'Alice'}
				String ticketToBob = (Kab).concat(String.valueOf(from));
				int value = new Random().nextInt(100000000) + 1;
				String iv = String.format("%08d", value);

				// Encrypt ticket to Bob with K_Bob
				encryptedTicket = (td.encrypt(ticketToBob, iv));
				//encryptedTicket = (td.encryptecb(ticketToBob, iv));
				encryptedTicket = new StringBuilder().append(iv)
						.append(encryptedTicket).toString();
			}

			String encryptedToAlice = null;
			// Check if sender is 'Alice'
			if (from == 1) {

				// Generate message 2 to Alice
				String sendToAlice = N1.concat(String.valueOf(to))
						.concat(String.valueOf(Kab.length())).concat(Kab)
						.concat(encryptedTicket);
				int value = new Random().nextInt(100000000) + 1;
				String iv = String.format("%08d", value);

				// Encrypt message to Alice with K_Alice
				Encrypter td = new Encrypter(sharedkey_AliceKDC,
						Constants.CBC_ALGORITHM_WITH_PADDING);
				encryptedToAlice = td.encrypt(sendToAlice, iv);
				//encryptedToAlice = td.encryptecb(sendToAlice, iv);
				encryptedToAlice = new StringBuilder().append(iv)
						.append(encryptedToAlice).toString();
			}
			// Message 2 from KDC to Alice - K_Alice{N1, Bob, Kab, ticket to
			// Bob}
			out.println(encryptedToAlice);
			System.out.println("Sent message 2 from KDC to Alice");

			// End communication with Alice
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
