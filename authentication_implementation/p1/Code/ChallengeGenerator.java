package com;

import java.security.SecureRandom;

public class ChallengeGenerator {


	public static String generatechallenge() {

		// Generate 64-bit nonces required for authentication
		SecureRandom random = new SecureRandom(); 
		long challenge = random.nextLong();
		String s = Long.toBinaryString(challenge);

		// Ensure that the nonces are all 64-bits long
		if (s.length() != 64) {
			while (s.length() < 64) {
				s = new StringBuilder().append("0").append(s).toString();
			}
		}
		return s;
	}

}
