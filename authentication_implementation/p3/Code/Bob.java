package com;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Random;

// Bob is the server
public class Bob extends Thread {

	// Shared key between Bob and KDC used to generate two keys for 3DES
	private static String sharedkey_BobKDC = Constants.K_BOB_KDC;

	// Server socket for Bob
	private Socket serversocket = null;

	// Keeps track of the number of client requests that Bob is servicing
	public static int firstThread = 0;

	// Constructor for Bob
	public Bob(Socket serversocket) {
		this.serversocket = serversocket;
		if (firstThread == 0)
			System.out.println("Session with Alice");
		else {
			System.out.println("");
			System.out.println("Session " + firstThread
					+ " with Trudy impersonating Alice");
		}
		firstThread++;
	}

	public void run() {

		try {

			// I/O streams for Bob
			PrintWriter out = new PrintWriter(serversocket.getOutputStream(),
					true);
			BufferedReader in = new BufferedReader(new InputStreamReader(
					serversocket.getInputStream()));

			// Receive message 3 from Alice to Bob - ticket, Kab{N2}
			String inputline1 = null;
			while ((inputline1 = in.readLine()) != null) {
				break;
			}
			System.out.println("Read message 3 from Alice to Bob");

			// Ticket from message 3
			int ticketLength = Integer.valueOf(inputline1.substring(0, 2));
			int Kab_length = Integer.valueOf(inputline1.substring(2, 4));
			String ticketToBob1 = inputline1.substring(4, ticketLength + 4);
			// Kab{N2} from message 3
			String iv = inputline1.substring(ticketLength + 4,
					ticketLength + 12);
			String encryptedChallenge = inputline1.substring(ticketLength + 12);

			// Decrypt nonce ticket from message 3
			Encrypter td = new Encrypter(sharedkey_BobKDC,
					Constants.CBC_ALGORITHM_WITH_PADDING);

			// Initialization vector - used only in CBC
			String iv1 = ticketToBob1.substring(0, 8);
			String ticketToBob = td.decrypt(ticketToBob1.substring(8), iv1);

			// Decrypt Kab from message 3
			String Kab = ticketToBob.substring(0, Kab_length);
			// Decrypt 'Alice' from message 3
			int from = Integer.valueOf(ticketToBob.substring(Kab_length,
					Kab_length + 1));

			// Check whether the shared key can be used with 'Alice'
			if (from == (Constants.ALICE)) {
				System.out.println("Alice received correctly");
			} else {
				System.out.println("Alice not received correctly !!!");
			}

			System.out.println("*******ECB encryption*******");

			Encrypter td1 = new Encrypter(Kab,
					Constants.ECB_ALGORITHM_WITHOUT_PADDING);

			// Decrypt nonce N2 from message 3
			String decrypted = td1.decryptecb(encryptedChallenge, iv);

			// Calculate N2-1
			BigInteger N2 = new BigInteger(decrypted, 2);
			BigInteger bi1;
			bi1 = new BigInteger("-1");
			BigInteger N2min1 = N2.add(bi1);
			String n2m1 = N2min1.toString(2);
			// Ensure N2-1 is 64 bits long
			if (n2m1.length() != 64) {
				while (n2m1.length() < 64) {
					n2m1 = new StringBuilder().append("0").append(n2m1)
							.toString();
				}
			}

			// Generate nonce N3
			String N3 = ChallengeGenerator.generatechallenge();

			// Calculate N2-1 concatenated with N3
			String toAlice;
			if (firstThread == 2)
				toAlice = N3.concat(n2m1);
			else
				toAlice = n2m1.concat(N3);

			// Initialization vector for CBC
			int val = new Random().nextInt(100000000) + 1;
			String iv2 = String.format("%08d", val);

			// Encrypt N2-1 concatenated with N3 with Kab
			String newEncrypted = td1.encryptecb(toAlice, iv2);
			System.out.println("Message 4 from Bob to Alice: " + newEncrypted);
			newEncrypted = new StringBuilder().append(iv2).append(newEncrypted)
					.toString();

			// Message 4 to Alice - Kab{N2-1, N3}
			out.println(newEncrypted);
			System.out.println("Sent message 4 from Bob to Alice");

			// Receive message 5 from Alice to Bob - Kab{N3-1}
			String inputline2 = null;
			while ((inputline2 = in.readLine()) != null) {
				break;
			}
			System.out.println("Read message 5 from Alice to Bob");

			// Initialization vector for CBC
			String iv3 = inputline2.substring(0, 8);

			// Decrypt N3-1 from message 5
			String N3rcv = td1.decryptecb(inputline2.substring(8), iv3);

			// Calculate (N3-1) + 1 = N3 from the value received in message 5
			BigInteger N3c = new BigInteger(N3rcv, 2);
			BigInteger bi2;
			bi2 = new BigInteger("1");
			BigInteger N3check = N3c.add(bi2);
			String n3m1 = N3check.toString(2);
			// Ensure N2 is 64 bits long
			if (n3m1.length() != 64) {
				while (n3m1.length() < 64) {
					n3m1 = new StringBuilder().append("0").append(n3m1)
							.toString();
				}
			}

			// Check for N3
			if (N3.equals(n3m1)) {
				System.out
						.println("N3 received correctly - Alice authenticated !!!");
			} else {
				System.out.println("Alice not authenticated !!!");
			}

			System.out.println("");

			// Receive message 3 from Alice to Bob - ticket, Kab{N2}
			String inputline1cbc = null;
			while ((inputline1cbc = in.readLine()) != null) {
				break;
			}
			System.out.println("Read message 3 from Alice to Bob");

			// Nonce N2 from message 3
			String encryptedChallengecbc = inputline1cbc
					.substring(ticketLength + 12);

			System.out.println("*******CBC encryption*******");
			Encrypter td1cbc = new Encrypter(Kab,
					Constants.CBC_ALGORITHM_WITHOUT_PADDING);

			// Decrypt nonce N2 from message 3
			String decrypted_cbc = td1cbc.decrypt(encryptedChallengecbc, iv);

			// Calculate N2-1
			BigInteger N2_cbc = new BigInteger(decrypted_cbc, 2);
			BigInteger bi1_cbc;
			bi1_cbc = new BigInteger("-1");
			BigInteger N2min1_cbc = N2_cbc.add(bi1_cbc);
			String n2m1_cbc = N2min1_cbc.toString(2);
			// Ensure N2-1 is 64 bits long
			if (n2m1_cbc.length() != 64) {
				while (n2m1_cbc.length() < 64) {
					n2m1_cbc = new StringBuilder().append("0").append(n2m1_cbc)
							.toString();
				}
			}

			// Calculate N2-1 concatenated with N3
			String toAlice_cbc;
			if (firstThread == 2)
				toAlice_cbc = N3.concat(n2m1_cbc);
			else
				toAlice_cbc = n2m1_cbc.concat(N3);

			// Encrypt N2-1 concatenated with N3 with Kab
			String newEncrypted_cbc = td1cbc.encrypt(toAlice_cbc, iv2);
			System.out.println("Message 4 from Bob to Alice: " + newEncrypted);

			newEncrypted_cbc = new StringBuilder().append(iv2)
					.append(newEncrypted_cbc).toString();

			// Message 4 to Alice - Kab{N2-1, N3}
			out.println(newEncrypted_cbc);
			System.out.println("Sent message 4 from Bob to Alice");

			// Receive message 5 from Alice to Bob - Kab{N3-1}
			String inputline2_cbc = null;
			while ((inputline2_cbc = in.readLine()) != null) {
				break;
			}
			System.out.println("Read message 5 from Alice to Bob");

			// Decrypt N3-1 from message 5
			String N3rcv_cbc = td1cbc.decrypt(inputline2_cbc.substring(8), iv3);

			// Calculate (N3-1) + 1 = N3 from the value received in message 5
			BigInteger N3c_cbc = new BigInteger(N3rcv_cbc, 2);
			BigInteger bi2_cbc;
			bi2_cbc = new BigInteger("1");
			BigInteger N3check_cbc = N3c_cbc.add(bi2_cbc);
			String n3m1_cbc = N3check_cbc.toString(2);
			// Ensure N2 is 64 bits long
			if (n3m1_cbc.length() != 64) {
				while (n3m1_cbc.length() < 64) {
					n3m1_cbc = new StringBuilder().append("0").append(n3m1_cbc)
							.toString();
				}
			}

			// Check for N3
			if (N3.equals(n3m1_cbc)) {
				System.out
						.println("N3 received correctly - Alice authenticated !!!");
			} else {
				System.out.println("Alice not authenticated !!!");
			}

			// End communication with Alice
			out.close();
			in.close();
			serversocket.close();

		} catch (IOException e) {
			System.out.println("Came here");
			// e.printStackTrace();
		} catch (NullPointerException e) {
			System.out
					.println("\n Session was terminated since all the required messages weren't received.");
		} catch (Exception e) {
			System.out.println("Or came here");
			// e.printStackTrace();

		}

	}

}
