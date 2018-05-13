import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.Certificate;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;

@SuppressWarnings({ "unused", "deprecation" })
public class Certificates implements Serializable {

	public static void main(String[] args) throws Exception{

		int keysize = 1024;
		Certificates c = new Certificates();
		Hash_and_Encrypt eh = new Hash_and_Encrypt();
		CertAndKeyGen keypair= eh.generateKeyPair(keysize);
		KeyStore ks =c.createCetificate("cert", "client.keystore","password",keypair);
		java.security.cert.Certificate certificate= ks.getCertificate("cert");
		System.out.println("Certificate1: "+ certificate.toString());

		KeyStore ks2 =c.createCetificate("cert2", "client2.keystore","password",keypair);
		java.security.cert.Certificate certificate2= ks2.getCertificate("cert2");
		System.out.println("Ceritificate2: " + certificate2.toString());

	}    






	KeyStore createCetificate (String alias, String KeyStoreName, String password,CertAndKeyGen keypair) throws Exception{

		String commonName = "Quasar"; //entity name
		String organizationalUnit = "NetworkSecurity";
		String organization = "BITS";
		String city = "HYD";
		String state = "AP";
		String country = "IN";
		long validity = 1096; // 3 years
		//String alias = "CERT";
		char[] keyPass = password.toCharArray();


		//create an empty keystore
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, null);


		//define entity holding certificate name and attributes
		X500Name x500Name = new X500Name(commonName, organizationalUnit, organization, city, state, country);


		//get the private key part
		PrivateKey privKey = keypair.getPrivateKey();


		//creating the certificate
		X509Certificate[] chain = new X509Certificate[1];
		chain[0] = keypair.getSelfCertificate(x500Name, new Date(), (long) validity * 24 * 60 * 60);

		//assigns the given private key to the given alias, protecting it with the given password and associating it with the given certificate . 
		keyStore.setKeyEntry(alias, privKey, keyPass, chain);

		//Stores this keystore to the given output stream, and protects its integrity with the given password.
		keyStore.store(new FileOutputStream(KeyStoreName), keyPass);

		//Loads this KeyStore from the given input stream. 
		keyStore.load(new FileInputStream(KeyStoreName), keyPass);


		return keyStore;



	} 


}