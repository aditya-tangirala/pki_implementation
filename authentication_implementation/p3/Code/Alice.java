package com;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Random;

// Alice is the client
public class Alice {

	// Shared key between Alice and KDC used to generate two keys for 3DES
	private static String sharedkey_AliceKDC = Constants.K_ALICE_KDC;

	public static void main(String[] args) {

		String host = "localhost";
		try {

			// Socket to communicate with KDC
			InetAddress address = InetAddress.getByName(host);
			Socket clientsocket1 = new Socket(address, 5555);
			PrintWriter out1 = new PrintWriter(clientsocket1.getOutputStream(),
					true);
			BufferedReader in1 = new BufferedReader(new InputStreamReader(
					clientsocket1.getInputStream()));

			// Nonce N1 is generated
			String N1 = ChallengeGenerator.generatechallenge();

			// Message 1 from Alice to KDC - N1, Alice wants Bob
			String aliceToKDC = N1.concat(String.valueOf(Constants.ALICE))
					.concat(String.valueOf(Constants.BOB));
			out1.println(aliceToKDC);
			System.out.println("Sent message 1 from Alice to KDC");

			// Read message 2 from KDC to Alice - K_Alice{N1, Bob, Kab, ticket
			// to Bob}
			String inputline;
			while ((inputline = in1.readLine()) != null) {
				break;
			}
			System.out.println("Read message 2 from KDC to Alice");

			// Decrypt the message 2 from KDC
			Encrypter td = new Encrypter(sharedkey_AliceKDC,
					Constants.CBC_ALGORITHM_WITHOUT_PADDING);

			// The initialization vector (iv) is used only for CBC encryption.
			// In ECB, its a dummy variable that is passed but not used.
			String iv = inputline.substring(0, 8);
			String decrypted = td.decrypt(inputline.substring(8), iv);
			// String decrypted = td.decryptecb(inputline.substring(8), iv);

			// N1 from message 2
			String N1check = decrypted.substring(0, 64);
			// 'Bob' from message 2
			int tocheck = Integer.parseInt(decrypted.substring(64, 65));
			// Kab from message 2
			int Kab_length = Integer.parseInt(decrypted.substring(65, 67));
			String Kab = decrypted.substring(67, 67 + Kab_length);
			// Ticket to Bob from message 2
			String ticketToBob = decrypted.substring(67 + Kab_length);

			// Check whether N1 received = N1 sent
			if (N1.equals(N1check)) {
				System.out.println("N1 received correctly");
			} else {
				System.out.println("N1 not received correctly !!!");
			}

			// Check whether the shared key can be used with 'Bob', as requested
			if (tocheck == (Constants.BOB)) {
				System.out.println("Bob received correctly");
			} else {
				System.out.println("Bob not received correctly !!!");
			}

			// End of communication with KDC
			in1.close();
			out1.close();
			clientsocket1.close();

			// Socket to communicate with Bob
			Socket clientsocket = new Socket(address, 4444);
			PrintWriter out = new PrintWriter(clientsocket.getOutputStream(),
					true);
			BufferedReader in = new BufferedReader(new InputStreamReader(
					clientsocket.getInputStream()));

			// Nonce N2 is generated
			String N2 = ChallengeGenerator.generatechallenge();

			// Initialization vector is generated for CBC encryption. This is
			// not used for ECB encryption
			int val = new Random().nextInt(100000000) + 1;
			String iv1 = String.format("%08d", val);

			System.out.println("*******ECB encryption*******");

			Encrypter td1 = new Encrypter(Kab,
					Constants.ECB_ALGORITHM_WITHOUT_PADDING);

			// Encrypt the nonce N2 with key Kab and send to Bob
			String encrypted = td1.encryptecb(N2, iv1);

			// Message 3 from Alice to Bob - ticket, Kab{N2}
			String toBob = String.valueOf(ticketToBob.length())
					.concat(String.valueOf(Kab_length)).concat(ticketToBob)
					.concat(iv1).concat(encrypted);
			out.println(toBob);
			System.out.println("Sent message 3 from Alice to Bob");

			// Receive message 4 from Bob - Kab{N2-1, N3}
			String inputline2 = null;
			while ((inputline2 = in.readLine()) != null) {
				break;
			}
			System.out.println("Read message 4 from Bob to Alice");

			// Initialization vector - only for CBC encryption
			String iv2 = inputline2.substring(0, 8);

			// Decrypt message 4 received from Bob
			String newdecrypt = td1.decryptecb(inputline2.substring(8), iv2);

			// N2-1 from message 4
			String N2c = newdecrypt.substring(0, 64);
			// N3 from message 4
			String N3rcv = newdecrypt.substring(64);

			// Calculate (N2-1) + 1 = N2 from the value received in message 4
			BigInteger N2check = new BigInteger(N2c, 2);
			BigInteger bi1;
			bi1 = new BigInteger("1");
			BigInteger N2min1 = N2check.add(bi1);
			String n2m1 = N2min1.toString(2);
			// Ensure N2 is 64 bits long
			if (n2m1.length() != 64) {
				while (n2m1.length() < 64) {
					n2m1 = new StringBuilder().append("0").append(n2m1)
							.toString();
				}
			}

			// Check for N2
			if (N2.equals(n2m1)) {
				System.out
						.println("N2 received correctly - Bob authenticated !!!");
			} else {
				System.out.println("Bob not authenticated !!!");
			}

			// Calculate N3-1 from N3 received in message 4
			BigInteger N3 = new BigInteger(N3rcv, 2);
			BigInteger bi2;
			bi2 = new BigInteger("-1");
			BigInteger N3m1 = N3.add(bi2);
			String n3m1 = N3m1.toString(2);
			// Ensure N3-1 is 64 bits long
			if (n3m1.length() != 64) {
				while (n3m1.length() < 64) {
					n3m1 = new StringBuilder().append("0").append(n3m1)
							.toString();
				}
			}

			// Initialization vector for CBC encryption only
			int val1 = new Random().nextInt(100000000) + 1;
			String iv3 = String.format("%08d", val1);

			// Encrypt N3-1 with Kab
			String finalString = td1.encryptecb(n3m1, iv3);
			System.out.println("Message 5 from Bob to Alice: " + finalString);

			// Message 5 from Alice to Bob - Kab{N3-1}
			finalString = new StringBuilder().append(iv3).append(finalString)
					.toString();
			out.println(finalString);
			System.out.println("Sent message 5 from Alice to Bob");

			System.out.println("");

			System.out.println("*******CBC encryption*******");
			Encrypter td1cbc = new Encrypter(Kab,
					Constants.CBC_ALGORITHM_WITHOUT_PADDING);

			// Encrypt the nonce N2 with key Kab and send to Bob
			String encrypted_cbc = td1cbc.encrypt(N2, iv1);
			// String encrypted = td1.encryptecb(N2, iv1);

			// Message 3 from Alice to Bob - ticket, Kab{N2}
			String toBob_cbc = String.valueOf(ticketToBob.length())
					.concat(String.valueOf(Kab_length)).concat(ticketToBob)
					.concat(iv1).concat(encrypted_cbc);
			out.println(toBob_cbc);
			System.out.println("Sent message 3 from Alice to Bob");

			// Receive message 4 from Bob - Kab{N2-1, N3}
			String inputline2_cbc = null;
			while ((inputline2_cbc = in.readLine()) != null) {
				break;
			}
			System.out.println("Read message 4 from Bob to Alice");

			// Decrypt message 4 received from Bob
			String newdecrypt_cbc = td1cbc.decrypt(inputline2_cbc.substring(8),
					iv2);

			// N2-1 from message 4
			String N2c_cbc = newdecrypt_cbc.substring(0, 64);
			// N3 from message 4
			String N3rcv_cbc = newdecrypt_cbc.substring(64);

			// Calculate (N2-1) + 1 = N2 from the value received in message 4
			BigInteger N2check_cbc = new BigInteger(N2c_cbc, 2);
			BigInteger bi1_cbc;
			bi1_cbc = new BigInteger("1");
			BigInteger N2min1_cbc = N2check_cbc.add(bi1_cbc);
			String n2m1_cbc = N2min1_cbc.toString(2);
			// Ensure N2 is 64 bits long
			if (n2m1_cbc.length() != 64) {
				while (n2m1_cbc.length() < 64) {
					n2m1_cbc = new StringBuilder().append("0").append(n2m1_cbc)
							.toString();
				}
			}

			// Check for N2
			if (N2.equals(n2m1_cbc)) {
				System.out
						.println("N2 received correctly - Bob authenticated !!!");
			} else {
				System.out.println("Bob not authenticated !!!");
			}

			// Calculate N3-1 from N3 received in message 4
			BigInteger N3_cbc = new BigInteger(N3rcv_cbc, 2);
			BigInteger bi2_cbc;
			bi2_cbc = new BigInteger("-1");
			BigInteger N3m1_cbc = N3_cbc.add(bi2_cbc);
			String n3m1_cbc = N3m1_cbc.toString(2);
			// Ensure N3-1 is 64 bits long
			if (n3m1_cbc.length() != 64) {
				while (n3m1_cbc.length() < 64) {
					n3m1_cbc = new StringBuilder().append("0").append(n3m1_cbc)
							.toString();
				}
			}

			// Encrypt N3-1 with Kab
			String finalString_cbc = td1cbc.encrypt(n3m1_cbc, iv3);
			System.out.println("Message 5 from Bob to Alice: " + finalString);

			// Message 5 from Alice to Bob - Kab{N3-1}
			finalString_cbc = new StringBuilder().append(iv3)
					.append(finalString_cbc).toString();
			out.println(finalString_cbc);
			System.out.println("Sent message 5 from Alice to Bob");

			// End of communication with Bob
			in.close();
			out.close();
			clientsocket.close();

			/*
			 * This message 3 is also sent to Trudy. In an actual environment,
			 * Trudy would be sniffing this information. But in our program, we
			 * can assume that the information that Trudy needs is available to
			 * her.
			 */
			Socket clientsocket2 = new Socket(address, 6666);
			PrintWriter out2 = new PrintWriter(clientsocket2.getOutputStream(),
					true);
			BufferedReader in2 = new BufferedReader(new InputStreamReader(
					clientsocket2.getInputStream()));
			out2.println(toBob);
			out2.println(toBob_cbc);

			in2.close();
			out2.close();
			clientsocket2.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
