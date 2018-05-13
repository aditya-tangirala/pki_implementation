package com;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;

public class TripleDES {

	// 3DES algorithm used - in CBC mode, with padding
	public static final String ALGORITHM = "DESede";
	public static final String TRANSFORMATION = "DESede/CBC/PKCS5Padding";
	private static final String UNICODE_FORMAT = "UTF8";

	public byte[] keyValue;
	public SecretKey key;

	public IvParameterSpec iv;
	Cipher encrypter;
	Cipher decrypter;

	public TripleDES(String sharedkey) throws Exception {

		// Variables required for the 2 keys' generation used in 3DES
		keyValue = sharedkey.getBytes(UNICODE_FORMAT);
		DESedeKeySpec keySpec = new DESedeKeySpec(keyValue);
		key = SecretKeyFactory.getInstance(ALGORITHM).generateSecret(keySpec);

		/* Initialization Vector of 8 bytes set to zero. */
		iv = new IvParameterSpec(new byte[8]);

		encrypter = Cipher.getInstance(TRANSFORMATION);
		decrypter = Cipher.getInstance(TRANSFORMATION);
	}

	// Encrypts the input String
	public String encrypt(String unencryptedString) {
		String encryptedString = null;
		try {

			encrypter.init(Cipher.ENCRYPT_MODE, key, iv);
			byte[] plainText = unencryptedString.getBytes(UNICODE_FORMAT);
			byte[] encryptedText = encrypter.doFinal(plainText);
			encryptedString = new String(Base64.encodeBase64(encryptedText));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encryptedString;
	}

	// Decrypts the input String
	public String decrypt(String encryptedString) {
		String decryptedText = null;
		try {
			decrypter.init(Cipher.DECRYPT_MODE, key, iv);
			byte[] encryptedText = Base64.decodeBase64(encryptedString);
			byte[] plainText = decrypter.doFinal(encryptedText);
			decryptedText = new String(plainText);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decryptedText;
	}

	
}
