package com;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;

// Alice is the client
public class Alice {

	// Shared key between Alice and KDC used to generate two keys for 3DES
	private static String sharedkey_AliceKDC = Constants.K_ALICE_KDC;

	public static void main(String[] args) {

		String host = "localhost";
		try {

			// Socket to communicate with Bob
			InetAddress address = InetAddress.getByName(host);
			Socket clientsocket = new Socket(address, 4444);
			PrintWriter out = new PrintWriter(clientsocket.getOutputStream(),
					true);
			BufferedReader in = new BufferedReader(new InputStreamReader(
					clientsocket.getInputStream()));

			// Message 1 from Alice to Bob - I want to talk to you
			String s = Constants.INITIATE_CONVERSATION;
			out.println(s);
			System.out.println("Sent message 1 from Alice to Bob");

			// Message 2 received from Bob - K_Bob{Nb}
			String inputline;
			while ((inputline = in.readLine()) != null) {
				break;
			}
			System.out.println("Read message 2 from Bob to Alice");

			// Generate nonce N1
			String N1 = ChallengeGenerator.generatechallenge();

			// Create message for KDC
			String aliceToKDC = N1.concat(String.valueOf(Constants.ALICE))
					.concat(String.valueOf(Constants.BOB)).concat(inputline);

			// Socket to communicate with KDC
			Socket clientsocket1 = new Socket(address, 5555);
			PrintWriter out1 = new PrintWriter(clientsocket1.getOutputStream(),
					true);
			BufferedReader in1 = new BufferedReader(new InputStreamReader(
					clientsocket1.getInputStream()));

			// Send message 3 to KDC - N1, Alice wants Bob, K_Bob{Nb}
			out1.println(aliceToKDC);
			System.out.println("Sent message 3 from Alice to KDC");

			// Message 4 received from KDC - K_Alice{N1, Bob, Kab, ticket
			// to Bob}
			String inputline1 = null;
			while ((inputline1 = in1.readLine()) != null) {
				break;
			}
			System.out.println("Read message 4 from KDC to Alice");

			// Decrypt message 4 from KDC using K_Alice
			TripleDES td = new TripleDES(sharedkey_AliceKDC);
			String decrypted = td.decrypt(inputline1);

			// N1 from message 4
			String N1check = decrypted.substring(0, 64);
			// 'Bob' from message 4
			int tocheck = Integer.parseInt(decrypted.substring(64, 65));
			// Kab from message 4
			int Kab_length = Integer.parseInt(decrypted.substring(65, 67));
			String Kab = decrypted.substring(67, 67 + Kab_length);
			// Ticket to Bob from message 4
			String ticketToBob = decrypted.substring(67 + Kab_length);

			// Check if N1 sent = N1 received
			if (N1.equals(N1check)) {
				System.out.println("N1 received correctly");
			} else {
				System.out.println("N1 not received correctly !!!");
			}

			// Check if 'Bob' received correctly
			if (tocheck == (Constants.BOB)) {
				System.out.println("Bob received correctly");
			} else {
				System.out.println("Bob not received correctly !!!");
			}

			// End communication with KDC
			in1.close();
			out1.close();
			clientsocket1.close();

			// Generate nonce N2
			String N2 = ChallengeGenerator.generatechallenge();

			// Encrypt N2
			TripleDES td1 = new TripleDES(Kab);
			String encrypted = td1.encrypt(N2);

			// Message 5 from Alice to Bob - ticket, Kab{N2}
			String toBob = String.valueOf(ticketToBob.length())
					.concat(String.valueOf(Kab_length)).concat(ticketToBob)
					.concat(encrypted);
			out.println(toBob);
			System.out.println("Sent message 5 from Alice to Bob");

			// Receive message 6 from Bob - Kab{N2-1, N3}
			String inputline2 = null;
			while ((inputline2 = in.readLine()) != null) {
				break;
			}
			System.out.println("Read message 6 from Bob to Alice");

			// Decrypt message 6
			String newdecrypt = td1.decrypt(inputline2);

			String N2c = newdecrypt.substring(0, 64);
			String N3rcv = newdecrypt.substring(64);

			// Check if N2 sent = N2 received
			BigInteger N2check = new BigInteger(N2c, 2);
			BigInteger bi1;
			bi1 = new BigInteger("1");
			BigInteger N2min1 = N2check.add(bi1);
			String n2m1 = N2min1.toString(2);
			if (n2m1.length() != 64) {
				while (n2m1.length() < 64) {
					n2m1 = new StringBuilder().append("0").append(n2m1)
							.toString();
				}
			}
			if (N2.equals(n2m1)) {
				System.out.println("N2 received correctly - Bob authenticated");
			} else {
				System.out.println("Bob not authenticated !!!");
			}

			// Calculate N3-1
			BigInteger N3 = new BigInteger(N3rcv, 2);
			BigInteger bi2;
			bi2 = new BigInteger("-1");
			BigInteger N3m1 = N3.add(bi2);
			String n3m1 = N3m1.toString(2);
			if (n3m1.length() != 64) {
				while (n3m1.length() < 64) {
					n3m1 = new StringBuilder().append("0").append(n3m1)
							.toString();
				}
			}

			// Message 7 from Alice to Bob - Kab{N3}
			String finalString = td1.encrypt(n3m1);
			out.println(finalString);
			System.out.println("Sent message 7 from Alice to Bob");

			// End communication with Bob
			in.close();
			out.close();
			clientsocket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
