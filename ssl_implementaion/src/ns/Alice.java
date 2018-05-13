/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package ns;

/**
 *
 * @author rajat
 */
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.apache.commons.lang3.ArrayUtils;

import sun.security.x509.CertAndKeyGen;

@SuppressWarnings("unused")
public
class Alice {
	public static void main(String[] arstring) throws Exception, IOException {

		int talkReq =1;
		String supported_enc="AES";
		String supported_int= "SHA1";
		String cipher_supported = supported_enc+"x"+supported_int; //defines data encryption and integrity protection scheme to use
		SecureRandom rand = new SecureRandom(); 
		long R_A;

		//opening socket with Bob
		Socket socket_Bob = new Socket("localhost", 6852);
		OutputStream ostream_Bob = socket_Bob.getOutputStream();
		PrintWriter toBob = new PrintWriter(ostream_Bob, true);
		InputStream istream_Bob = new DataInputStream(socket_Bob.getInputStream());
		BufferedReader fromBob = new BufferedReader(new InputStreamReader(socket_Bob.getInputStream()));

		ObjectOutputStream oostream_Bob = new ObjectOutputStream(ostream_Bob);  
		ObjectInputStream oistream_Bob = new ObjectInputStream(istream_Bob);  

		ArrayList<Byte> msg_bytes = new ArrayList<Byte>();


		//creating output file
		File file;
		FileWriter fw = null;
		BufferedWriter bw;
		file = new File("SSL_Alice.txt");
		try {
			fw = new FileWriter(file.getAbsoluteFile());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		bw = new BufferedWriter(fw);


		bw.write("Alice started \n");
		System.out.println("Alice started ");

		bw.write("==============================================================================\n");
		bw.write("HandShake Phase started at Alice \n");
		bw.write("==============================================================================\n");
		//System.out.println("==============================================================================\n");
		System.out.println("HandShake Phase started at Alice ");
		//System.out.println("==============================================================================\n");


		//generating Alice certificate
		Certificates c_A = new Certificates();
		Hash_and_Encrypt eh = new Hash_and_Encrypt();

		//generating public/private key pair
		int keysize = 1024;
		CertAndKeyGen keypair= eh.generateKeyPair(keysize);

		//get the public/private key part
		PrivateKey privKey_Alice = keypair.getPrivateKey();
		PublicKey pubKey_Alice = keypair.getPublicKey();

		KeyStore ks =c_A.createCetificate("cert_A", "Alice.keystore","Alicepassword",keypair);
		X509Certificate cert_A= (X509Certificate) ks.getCertificate("cert_A");

                
		bw.write("Alice generating cert_A \n");
		System.out.println("Alice generating cert_A ");

		bw.write("cert_A= ");
		bw.write(cert_A.toString());
		bw.write("\n");
		System.out.println("cert_A=  "+cert_A.toString());

		//Alice sending talkReq, cipher_supported, cert_A to Bob
		System.out.println("Cipher Supported: " +cipher_supported);

		bw.write("Alice sending talkReq, cipher_supported, cert_A to Bob \n");
		System.out.println("Alice sending talkReq, cipher_supported, cert_A to Bob ");

		oostream_Bob.writeObject(talkReq);  
		oostream_Bob.writeObject(cipher_supported);
		oostream_Bob.writeObject(cert_A);  
		System.out.flush();

		byte[] talk_Req_b =ByteBuffer.allocate(4).putInt(talkReq).array();
		msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(talk_Req_b)));
		byte[] cipher_supported_b= cipher_supported.getBytes();
		msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(cipher_supported_b)));
		byte[] cert_A_b = cert_A.getEncoded();
		msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(cert_A_b)));

		//receiving cert_B from Bob 
		X509Certificate cert_B = (X509Certificate)oistream_Bob.readObject();  

		byte[] cert_B_b = cert_B.getEncoded();
		msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(cert_B_b)));

		bw.write("Alice receiving cert_B  from Bob  \n");
		System.out.println("Alice receiving cert_B from Bob  ");

		bw.write("cert_B= ");
		bw.write(cert_B.toString());
		bw.write("\n");
		System.out.println("cert_B=  "+cert_B);

		//verifying cert_B
		bw.write("Alice verifying cert_B \n");
		System.out.println("Alice verifying cert_B  ");

		try{
			cert_B.checkValidity();
		}
		catch(Exception v){
			System.out.println("Certificate not valid. Exiting ......");
			System.exit(0);
		}

		try{
			cert_B.verify(  cert_B.getPublicKey());
		}
		catch(SignatureException s){
			System.out.println("Certificate not verified. Exiting ......");
			System.exit(0);

		}

		bw.write("cert_B verified  \n");
		System.out.println("cert_B verified  ");



		//extracting Bob's public key from the certificate 
		PublicKey pubKey_Bob = cert_B.getPublicKey();

		bw.write("Extracting Bob's public key from the certificate  \n");
		System.out.println("Extracting Bob's public key from the certificate   ");


		//generating R_A
		R_A=Math.abs(rand.nextLong());

		bw.write("Alice generating R_A \n");
		System.out.println("Alice generating R_A ");

		bw.write("R_A= ");
		bw.write(Long.toString(R_A));
		bw.write("\n");
		System.out.println("R_A=  "+R_A);

		//Encrypting R_A
		byte [] encrypted_R_A= eh.RSAEncrypt(R_A, pubKey_Bob);

		bw.write("Alice rncrypting and sending R_A \n");
		System.out.println("Alice encrypting and sending R_A ");


		//sending encrypted_R_A
		oostream_Bob.writeObject(encrypted_R_A);

		byte[] encrypted_R_A_b = encrypted_R_A;
		msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(encrypted_R_A_b)));

		//receiving encrypted_R_B
		byte [] encrypted_R_B = (byte[])oistream_Bob.readObject();  

		byte[] encrypted_R_B_b = encrypted_R_B;
		msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(encrypted_R_B_b)));

		bw.write("Alice receiving and decrypting  encrypted_R_b from Bob \n");
		System.out.println("Alice receiving and decrypting  encrypted_R_B from Bob ");

		//decrypting encrypted_R_B

		long R_B= eh.RSADecrypt(encrypted_R_B, privKey_Alice);

		bw.write("R_B= ");
		bw.write(Long.toString(R_B));
		bw.write("\n");
		System.out.println("R_B=  "+R_B);

		ArrayList<Byte> msg_bytes_B= new ArrayList<Byte>(msg_bytes);

		byte[] strClient = "Client".getBytes();
		//msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(strClient)));

		byte [] msg=  ArrayUtils.toPrimitive(msg_bytes.toArray(new Byte[msg_bytes.size()]));

		//hashing all exchanged messages+ "Client" using SHA-1
		byte [] MAC_A = eh.SHA1(msg);

		bw.write("Alice hashing all exchanged messages+ \"Client\" using SHA-1 \n");
		System.out.println("Alice hashing all exchanged messages+ \"Client\" using SHA-1 ");

		//sending hashed MAC_A
		oostream_Bob.writeObject(MAC_A);

		bw.write("Alice sending hashed MAC_A to Bob \n");
		System.out.println("Alice sending hashed MAC_A to Bob ");

		//receiving MAC_B
		byte [] MAC_B = (byte[])oistream_Bob.readObject();  

		bw.write("Alice receiving hashed MAC_B from Bob \n");
		System.out.println("Alice receiving hashed MAC_B from Bob ");

		//verifying MAC_B
		byte[] strServer = "Server".getBytes();
		msg_bytes_B.addAll(Arrays.asList(ArrayUtils.toObject(strServer)));
		byte [] msg_B=  ArrayUtils.toPrimitive(msg_bytes_B.toArray(new Byte[msg_bytes_B.size()]));
		//hashing all exchanged messages+"Server" using SHA-1
		byte [] _MAC_B = eh.SHA1(msg_B);


		bw.write("Alice verifying hashed MAC_B  \n");
		System.out.println("Alice verifying hashed MAC_B ");


		if(Arrays.equals(MAC_B, _MAC_B)){
			bw.write("Alice verified hashed MAC_B  \n");
			System.out.println("Alice verified hashed MAC_B ");
		}
		else{
			bw.write(" Hashed MAC_B not verified \n");
			System.out.println("Hashed MAC_B not verified ");

			bw.write(" Handshake phase failed at Alice \n");
			System.out.println("Handshake phase failed at Alice");
			System.exit(0);
		}


		//generating encryption and authentication keys
		long master_key = R_A ^ R_B;

		SecretKey enc_fromBob = eh.generateAESKey("ToAliceEncryption", master_key);
		SecretKey enc_toBob = eh.generateAESKey("ToBobEncryption", master_key);

		SecretKey hash_fromBob = eh.generateAESKey("ToAliceAuthentication", master_key);
		SecretKey hash_toBob = eh.generateAESKey("ToBobAuthentication", master_key);

		bw.write(" Alice generated required keys \n");
		System.out.println("Alice generated required keys ");

		bw.write("==============================================================================\n");
		bw.write("HandShake Phase successfully ended at Alice \n");
		bw.write("==============================================================================\n");
		System.out.println("==============================================================================\n");
		System.out.println("HandShake Phase successfully ended at Alice ");
		System.out.println("==============================================================================\n");


		bw.write("==============================================================================\n");
		bw.write("Data Exchange Phase started at Alice \n");
		bw.write("==============================================================================\n");
		System.out.println("==============================================================================\n");
		System.out.println("Data Exchange Phase started at Alice ");
		System.out.println("==============================================================================\n");


		//Alice reading a file with size > 50Kbytes

		bw.write("Alice dividing the file into chunks and formulating these chunks into SSL blocks \n");
		System.out.println("Alice dividing the file into chunks and formulating these chunks into SSL blocks ");


		FileInputStream in = null;

		try {
			in = new FileInputStream("second.pdf");

			int seq=0;
			byte[] RH= new byte[8];


			int count=0;
			byte [] tohash=new byte[1036];
			byte[] chunk = new byte[1024];
			int chunkLen = 0;
			while ((chunkLen = in.read(chunk)) != -1) {
				// formulate that chunk into SSL block

				//adding seq to SSL block to be hashed
				byte [] seq_b= ByteBuffer.allocate(4).putInt(seq).array();
				System.arraycopy(seq_b, 0, tohash, 0, seq_b.length);

				//adding RH to SSL block to be hashed
				//add the record type = 1 for data exchange
				RH[0]= 1;

				//add the SSL version = 3 
				RH[1]=3;

				//add the end of file indicator=0 meaning it is not the end of file yet
				RH[2]=0;
				if (chunkLen!=1024)
					//add the end of file indicator=1 meaning it is  the end of file 
					RH[2]=1;

				//add chunk length 
				byte [] chunkLen_b= ByteBuffer.allocate(4).putInt(chunkLen).array();
				System.arraycopy(chunkLen_b, 0, RH, 3, chunkLen_b.length);

				//add the record header length= 8
				RH[7]=8;

				System.arraycopy(RH, 0, tohash, seq_b.length,RH.length );

				//adding data to SSL block to be hashed
				System.arraycopy(chunk, 0, tohash, seq_b.length+RH.length,chunk.length );

				//hashing seq,record header, data
				byte [] HMAC = eh.SHA1(tohash);

				byte[] toencrypt = new byte [chunk.length+HMAC.length];

				//adding data to SSL block to be encrypted
				System.arraycopy(chunk, 0, toencrypt, 0,chunk.length );

				//adding HMAC to SSL block to be encrypted
				System.arraycopy(HMAC, 0, toencrypt, chunk.length,HMAC.length );

				//encrypting data and HMAC
				byte [] encrypted = eh.AESencrypt(toencrypt, enc_toBob);

				byte [] tosend = new byte [RH.length+encrypted.length];

				//adding RH to SSL block to send
				System.arraycopy(RH, 0, tosend, 0,RH.length );

				//adding encrypted data to SSL block to send
				System.arraycopy(encrypted, 0, tosend, RH.length,encrypted.length );

				//adding HMAC to SSL block to send
				//System.arraycopy(HMAC, 0, tosend, RH.length+encrypted.length, HMAC.length );



				//sending the SSL block to Bob
				oostream_Bob.writeObject(tosend);

				seq++;

			}




		} finally {
			if (in != null) {
				in.close();
			}

		}

		bw.write("Alice sent the file to Bob \n");
		System.out.println("Alice sent the file to Bob ");


		bw.write("==============================================================================\n");
		bw.write("Data exchange Phase successfully ended at Alice \n");
		bw.write("==============================================================================\n");
		System.out.println("==============================================================================\n");
		System.out.println("Data exchange Phase successfully ended at Alice ");
		System.out.println("==============================================================================\n");

		//closing socket and streams
		ostream_Bob.close();
		istream_Bob.close();
		oostream_Bob.close();
		oistream_Bob.close();
		bw.close();
		socket_Bob.close();


	}
}