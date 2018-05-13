package com;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class Trudy {

	public static void main(String[] args) {

		// Server socket for Trudy
		ServerSocket firstsocket = null;
		Socket serversocket = null;
		String host = "localhost";

		try {
			firstsocket = new ServerSocket(6666);
		} catch (IOException e) {
			e.printStackTrace();
		}

		try {

			// Socket for communication with Alice.
			/*
			 * This message 3 is also sent to Trudy. In an actual environment,
			 * Trudy would be sniffing this information. But in our program, we
			 * can assume that the information that Trudy needs is available to
			 * her.
			 */
			serversocket = firstsocket.accept();
			PrintWriter out = new PrintWriter(serversocket.getOutputStream(),
					true);
			BufferedReader in = new BufferedReader(new InputStreamReader(
					serversocket.getInputStream()));
			String inputline = null;

			// Message 3 between Alice and Bob - ticket, Kab{N2}
			inputline = in.readLine();
			System.out
					.println("Trudy received message 3 from Alice to Bob by eavesdropping");

			out.close();
			in.close();
			serversocket.close();
			firstsocket.close();

			// Socket for communication with Bob, impersonating Alice - session
			// 1
			InetAddress address = InetAddress.getByName(host);
			Socket clientsocket1 = new Socket(address, 4444);
			PrintWriter out1 = new PrintWriter(clientsocket1.getOutputStream(),
					true);
			BufferedReader in1 = new BufferedReader(new InputStreamReader(
					clientsocket1.getInputStream()));

			int ticketLength = Integer.valueOf(inputline.substring(0, 2));
			int Kab_length = Integer.valueOf(inputline.substring(2, 4));
			String ticketToBob = inputline.substring(4, ticketLength + 4);

			// Replaying message 3 between Alice and Bob to Bob.
			out1.println(inputline);
			System.out.println("Trudy replays message 3 to Bob");

			// Receiving message 4 from Bob - Kab{N2-1, N4}
			String lineFromBob = null;
			lineFromBob = in1.readLine();
			System.out.println("Trudy receives message 4 from Bob");

			// Initialization vector - only for CBC
			String iv = lineFromBob.substring(0, 8);

			// Separating Kab{N4} from message 4 to use for reflection attack
			int len = ((lineFromBob.length() - 8) / 2);
			String n3FromBob = lineFromBob.substring(8, len + 8);

			// Creation of session 2 with Bob
			Socket clientsocket2 = new Socket(address, 4444);
			PrintWriter out2 = new PrintWriter(clientsocket2.getOutputStream(),
					true);
			BufferedReader in2 = new BufferedReader(new InputStreamReader(
					clientsocket2.getInputStream()));

			System.out.println("Trudy opens a new session with Bob");
			// Re-sending ticket received from Alice and sent to Bob in the
			// first session along with Kab{N4}
			String toBob = String.valueOf(ticketLength)
					.concat(String.valueOf(Kab_length)).concat(ticketToBob)
					.concat(iv).concat(n3FromBob);
			out2.println(toBob);
			System.out
					.println("Trudy re-sends ticket from message 3 along with encryted nonce received from Bob in message 4");

			// Receives Kab{N4-1, N5} from Bob
			String lineFromBob1 = null;
			lineFromBob1 = in2.readLine();
			System.out
					.println("Trudy receives message 4 from Bob in new session - contains Kab{N4-1}");

			// Initialization vector - only for CBC
			String iv1 = lineFromBob1.substring(0, 8);

			// Separating Kab{N4-1} from the previous message from Bob
			int len1 = (lineFromBob1.length() - 8) / 2;
			String sendToBobInFirstConnection = lineFromBob1.substring(8,
					len1 + 8);

			// Sending Kab{N4-1} as message 5 in 1st session with Bob
			String msg5ToBob = iv1.concat(sendToBobInFirstConnection);
			out1.println(msg5ToBob);
			System.out.println("Trudy sends Kab{N4-1} as message 5 in 1st session");

			// Terminating all communication with Bob since Trudy is
			// authenticated to be Alice in the 1st session with Bob.
			System.out.println("Trudy authenticated as Alice !!!");
			in1.close();
			out1.close();
			clientsocket1.close();

			in2.close();
			out2.close();
			clientsocket2.close();

		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
