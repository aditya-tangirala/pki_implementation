package com;

import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;

public class Encrypter {
	
	// Variable required for 3DES keys' generation
	private KeySpec keySpec;
	private SecretKey key;
	// Algorithm used for Encryption and Decryption
	private String algorithm;

	public Encrypter(String keyString, String algorithm) {
		try {
			
			// Key generation
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(Base64
					.decodeBase64(keyString.getBytes("utf-8")));
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			keySpec = new DESedeKeySpec(keyBytes);
			key = SecretKeyFactory.getInstance("DESede")
					.generateSecret(keySpec);
			this.algorithm = algorithm;

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Encryption function for CBC
	public String encrypt(String value, String ivString) {
		try {
			
			IvParameterSpec iv = new IvParameterSpec(ivString.getBytes());
			
			Cipher ecipher = Cipher.getInstance(algorithm);
			ecipher.init(Cipher.ENCRYPT_MODE, key, iv);

			// Encode the string into bytes using utf-8
			byte[] utf8 = value.getBytes("UTF8");

			// Encrypt
			byte[] enc = ecipher.doFinal(utf8);

			// Encode bytes to base64 to get a string
			return new String(Base64.encodeBase64(enc), "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	// Decryption function for CBC
	public String decrypt(String value, String ivString) {
		try {
			
			IvParameterSpec iv = new IvParameterSpec(ivString.getBytes());
			
			Cipher dcipher = Cipher.getInstance(algorithm);
			dcipher.init(Cipher.DECRYPT_MODE, key, iv);

			// Decode base64 to get bytes
			byte[] dec = Base64.decodeBase64(value.getBytes());

			// Decrypt
			byte[] utf8 = dcipher.doFinal(dec);

			// Decode using utf-8
			return new String(utf8, "UTF8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// Encryption function for ECB - Initialization vector not used
	public String encryptecb(String value, String ivString) {
		try {
			
			Cipher ecipher = Cipher.getInstance(algorithm);
			ecipher.init(Cipher.ENCRYPT_MODE, key);

			// Encode the string into bytes using utf-8
			byte[] utf8 = value.getBytes("UTF8");

			// Encrypt
			byte[] enc = ecipher.doFinal(utf8);

			// Encode bytes to base64 to get a string
			return new String(Base64.encodeBase64(enc), "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	// Decryption function for ECB - Initialization vector not used
	public String decryptecb(String value, String ivString) {
		try {
			
			Cipher dcipher = Cipher.getInstance(algorithm);
			dcipher.init(Cipher.DECRYPT_MODE, key);

			// Decode base64 to get bytes
			byte[] dec = Base64.decodeBase64(value.getBytes());

			// Decrypt
			byte[] utf8 = dcipher.doFinal(dec);

			// Decode using utf-8
			return new String(utf8, "UTF8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static void main(String[] args) {

		//String algorithm = "DESede/ECB/NoPadding";
		String algorithm = "DESede/CBC/NoPadding";
		
		Encrypter td = new Encrypter("This is my pwd.", algorithm);

		String plaintext = "1234567890123456789012345678901234567890123456789012345678901234";

		String newtext = "1234123456789012345678901234567890123456789012345678901234567890";

		String full = plaintext.concat(newtext);

		String iv = "12345678";
		String encrypted = td.encrypt(plaintext, iv);
		String decrypted = td.decrypt(encrypted, iv);

		String iv1 = "87654321";
		String encrypted1 = td.encrypt(newtext, iv1);
		String decrypted1 = td.decrypt(encrypted1, iv1);

		String iv2 = "13572468";
		String encrypted2 = td.encrypt(full, iv2);
		String decrypted2 = td.decrypt(encrypted2, iv2);
		
		/*String iv = "12345678";
		String encrypted = td.encryptecb(plaintext);
		String decrypted = td.decryptecb(encrypted);

		String iv1 = "87654321";
		String encrypted1 = td.encryptecb(newtext);
		String decrypted1 = td.decryptecb(encrypted1);

		String iv2 = "13572468";
		String encrypted2 = td.encryptecb(full);
		String decrypted2 = td.decryptecb(encrypted2);*/

		System.out.println("String To Encrypt x: " + plaintext);
		System.out.println("Encrypted String x: " + encrypted);
		System.out.println(encrypted.length());
		System.out.println("Decrypted String x: " + decrypted);
		System.out.println("");

		System.out.println("String To Encrypt y: " + newtext);
		System.out.println("Encrypted String y: " + encrypted1);
		System.out.println(encrypted1.length());
		System.out.println("Decrypted String y: " + decrypted1);
		System.out.println();

		System.out.println("String To Encrypt xy: " + full);
		System.out.println("Encrypted String xy: " + encrypted2);
		System.out.println(encrypted2.length());
		System.out.println("Decrypted String xy: " + decrypted2);
		System.out.println("");
		
		String iv3 = "67890123";
		int half = encrypted2.length()/2;
		String first = encrypted2.substring(0, half);
		String decrypted3 = td.decrypt(first, iv3);
		System.out.println("Decrypted String x from xy: " + decrypted3);
	}

}