package com;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;


// Bob is the server
public class Bob {

	// Shared key between Bob and KDC used to generate two keys for 3DES
	private static String sharedkey_BobKDC = Constants.K_BOB_KDC;
	
	public static void main(String[] args) {
		
		ServerSocket firstsocket = null;
		Socket serversocket = null;

		try {
			firstsocket = new ServerSocket(4444);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		try {
			
			// Server socket for Bob
			serversocket = firstsocket.accept();
			PrintWriter out = new PrintWriter(serversocket.getOutputStream(), true);
	        BufferedReader in = new BufferedReader(
	                new InputStreamReader(
	                		serversocket.getInputStream()));
	        
	        // Receive message 1 from Alice 
	        String inputline;        
	        int start = 0;	        
	        while ((inputline = in.readLine()) != null) {        	 
	        	if (inputline.equals(Constants.INITIATE_CONVERSATION)) {
	        		start = 1;
	        	}
	        	break;
	        }
	        System.out.println("Read message 1 from Alice to Bob");
	        
	        String Nb  = null;
	        TripleDES td = null;
	        if (start==1) {
	        	// Generate challenge
	        	Nb = ChallengeGenerator.generatechallenge(); 
	        	
	        	// Encrypt using K_Bob
	    		td = new TripleDES(sharedkey_BobKDC);

	    		String encrypted = td.encrypt(Nb);
	    		// Message 2 to Alice - K_Bob{N2}
	    		out.println(encrypted);
	    		System.out.println("Sent message 2 from Bob to Alice");
	        }
	        
	        // Receive message 5 from Alice -  ticket, Kab{N2}
	        String inputline1 = null;
	        while ((inputline1 = in.readLine()) != null) {
	        	break;
	        }
	        System.out.println("Read message 5 from Alice to Bob");
	        
	        // Ticket to Bob from message 5
	        int ticketLength = Integer.valueOf(inputline1.substring(0, 3));
	        int Kab_length = Integer.valueOf(inputline1.substring(3, 5));
	        String ticketToBob1 = inputline1.substring(5, ticketLength+5);

	        // Encrypted N2
	        String encryptedChallenge = inputline1.substring(ticketLength+5);
	        
	        // Decrypt ticket to Bob
	        String ticketToBob = td.decrypt(ticketToBob1);

	        // Kab from ticket
	        String Kab = ticketToBob.substring(0, Kab_length);
	        // 'Alice' from ticket
	        int from = Integer.valueOf(ticketToBob.substring(Kab_length , Kab_length+1));
	        
	        // Check whether Nb sent = Nb received
	        String Nbcheck = ticketToBob.substring(Kab_length+1);	        
	        if (Nb.equals(Nbcheck)) {
				System.out.println("Nb received correctly");
			} else {
				System.out.println("Nb not received correctly !!!");
			}
			
	        // Check whether 'Alice' received correctly
			if (from == (Constants.ALICE)) {
				System.out.println("Alice received correctly");
			} else {
				System.out.println("Alice not received correctly !!!");
			}
	        
			// Decrypt N2
			TripleDES td1 = new TripleDES(Kab);
			String decrypted = td1.decrypt(encryptedChallenge);
			
			// Calculate N2-1
			BigInteger N2 = new BigInteger(decrypted, 2);
			BigInteger bi1;
			bi1 = new BigInteger("-1");
			BigInteger N2min1 = N2.add(bi1) ;
			String n2m1 = N2min1.toString(2);
			if (n2m1.length() != 64) {
				while (n2m1.length() < 64) {
					n2m1 = new StringBuilder().append("0").append(n2m1).toString();
				}
			}
			
			// Generate nonce N3
			String N3 = ChallengeGenerator.generatechallenge();
			
			// Send message 6 to Alice - Kab{N2-1, N3}
			String toAlice = n2m1.concat(N3);
			String newEncrypted = td1.encrypt(toAlice);
			out.println(newEncrypted);
			System.out.println("Sent message 6 from Bob to Alice");
			
			// Receive message 7 from Alice - Kab{N3-1}
			String inputline2 = null;
	        while ((inputline2 = in.readLine()) != null) {
	        	break;
	        }
	        System.out.println("Read message 7 from Alice to Bob");
	        
	        // Check whether N3 sent = N3 received
	        String N3rcv = td1.decrypt(inputline2);			
			BigInteger N3c = new BigInteger(N3rcv, 2);
			BigInteger bi2;
			bi2 = new BigInteger("1");
			BigInteger N3check = N3c.add(bi2) ;
			String n3m1 = N3check.toString(2);
			if (n3m1.length() != 64) {
				while (n3m1.length() < 64) {
					n3m1 = new StringBuilder().append("0").append(n3m1).toString();
				}
			}
			if (N3.equals(n3m1)) {
				System.out.println("N3 received correctly - Alice authenticated");
			} else {
				System.out.println("Alice not authenticated !!!");
			}

			// End all communication with Alice
	        out.close();
	        in.close();
			serversocket.close();
			firstsocket.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
}
