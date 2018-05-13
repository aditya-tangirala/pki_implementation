/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package ns;

/**
 *
 * @author rajat
 */
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import sun.security.x509.CertAndKeyGen;


@SuppressWarnings("unused")
public class Hash_and_Encrypt {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		//generating Alice certificate
		Hash_and_Encrypt eh = new Hash_and_Encrypt();

		//generating public/private key pair
		int keysize = 1024;
		CertAndKeyGen keypair= eh.generateKeyPair(keysize);

		//get the public/private key part
		PrivateKey privKey_Alice = keypair.getPrivateKey();
		PublicKey pubKey_Alice = keypair.getPublicKey();
		long test= 86465484548L;

		Hash_and_Encrypt rsa= new Hash_and_Encrypt();
		byte[] outtest=rsa.RSAEncrypt(test,pubKey_Alice );

		System.out.println(outtest);

		long detest=rsa.RSADecrypt(outtest,privKey_Alice );
		System.out.println(detest);
		System.out.println(test);
		byte [] b={1,2,3,4};
		byte [] b1= rsa.SHA1(b);
		byte [] b2= rsa.SHA1(b);

		SecretKey secret = eh.generateAESKey("password", test);
		byte [] str = "AmalLotf12sfgrrdfhr".getBytes();
		byte[] out =eh.AESencrypt(str, secret);
		byte[] in =eh.AESdecrypt(out, secret);
		System.out.println("Result: " + new String(in));


	}


	public byte[] RSAEncrypt(long message, PublicKey pubKey) throws Exception {

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);

		final byte[] plainTextBytes = ByteBuffer.allocate(8).putLong(message).array();
		final byte[] cipherTextBytes = cipher.doFinal(plainTextBytes);
		//final ByteBuffer byteBuffer = ByteBuffer.wrap(cipherTextBytes);
		//long cipherText =byteBuffer.getLong(0);

		return cipherTextBytes;
	}

	public long RSADecrypt(byte[] message, PrivateKey privKey) throws Exception {

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privKey);

		//final byte[] cipherTextBytes = ByteBuffer.allocate(8).putLong(message).array();
		//	final byte[] plainTextBytes = cipher.doFinal(cipherTextBytes);
		final byte[] plainTextBytes = cipher.doFinal(message);
		final ByteBuffer byteBuffer = ByteBuffer.wrap(plainTextBytes);
		long plainText =byteBuffer.getLong(0);

		return plainText;
	}

	CertAndKeyGen generateKeyPair(int keysize) throws Exception{
		//specify  particular key type and signature algorithm
		CertAndKeyGen keypair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);

		//generates a random public/private key pair, with a given key size.
		keypair.generate(keysize);

		return keypair;
	}

	public SecretKey generateAESKey(String password,long master_key) throws Exception{

		final byte[] master_key_Bytes = ByteBuffer.allocate(8).putLong(master_key).array();
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec spec = new PBEKeySpec(password.toCharArray(), master_key_Bytes, 65536, 128);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");



		return secret;


	}


	public byte [] AESencrypt(byte [] message, SecretKey secret) throws Exception {


		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		final IvParameterSpec iv = new IvParameterSpec(new byte[16]);
		cipher.init(Cipher.ENCRYPT_MODE, secret,iv);
		byte[] encrypted = cipher.doFinal(message);
		//System.out.println("encrypted string:" + (encrypted.toString()));
		return (encrypted);

	}


	public byte [] AESdecrypt(byte [] message, SecretKey secret) throws Exception {


		//SecretKeySpec skeySpec = new SecretKeySpec(secret.getBytes(), "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		final IvParameterSpec iv = new IvParameterSpec(new byte[16]);

		cipher.init(Cipher.DECRYPT_MODE, secret,iv);
		byte[] original = cipher.doFinal(message);

		return original;
	}

	public  byte[] SHA1(byte[] mesaage)throws Exception {

		MessageDigest md = MessageDigest.getInstance("SHA-1");

		md.update(mesaage, 0, mesaage.length);

		byte[] mdbytes = md.digest();
		return mdbytes;


	}


}