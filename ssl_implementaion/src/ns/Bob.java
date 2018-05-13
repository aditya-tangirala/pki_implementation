/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package ns;

/**
 *
 * @author rajat
 */
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
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
class Bob {

	public static void main(String[] arstring) throws Exception {

		ServerSocket socket = new ServerSocket(6852);
		SecureRandom rand = new SecureRandom(); 
		long N_B;

		//creating output file
		File file;
		FileWriter fw = null;
		BufferedWriter bw;
		file = new File("SSL_Bob.txt");
		//file = new File("SSL_Bob_handshakefail.txt");
		try {
			fw = new FileWriter(file.getAbsoluteFile());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		bw = new BufferedWriter(fw);

		//accepting connection from Alice
		Socket connectionSocket = socket.accept();
		OutputStream ostream_Alice = connectionSocket.getOutputStream();
		InputStream istream_Alice = new DataInputStream(connectionSocket.getInputStream());
		PrintWriter toAlice = new PrintWriter(ostream_Alice, true);
		BufferedReader fromAlice = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

		ObjectOutputStream oostream_Alice = new ObjectOutputStream(ostream_Alice);  
		ObjectInputStream oistream_Alice= new ObjectInputStream(istream_Alice);  

		ArrayList<Byte> msg_bytes = new ArrayList<Byte>();


		bw.write("Bob started. \n");
		System.out.println("Bob started.");

		bw.write("==============================================================================\n");
		bw.write("HandShake Phase started at Bob \n");
		bw.write("==============================================================================\n");
		//System.out.println("==============================================================================\n");
		System.out.println("HandShake Phase started at Bob ");
		//System.out.println("==============================================================================\n");

		//receiving TalkReq,cipher_supported,cert_A from Alice 
		int talkReq = (Integer) oistream_Alice.readObject(); 
		String cipher_supported = (String)oistream_Alice.readObject();  
		X509Certificate cert_A = (X509Certificate) oistream_Alice.readObject();

		byte[] talk_Req_b =ByteBuffer.allocate(4).putInt(talkReq).array();
		msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(talk_Req_b)));
		byte[] cipher_supported_b= cipher_supported.getBytes();
		msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(cipher_supported_b)));
		byte[] cert_A_b = cert_A.getEncoded();
		msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(cert_A_b)));

		bw.write("Bob receiving TalkReq,cipher_supported,cert_A  from Alice  \n");
		System.out.println("Bob receiving TalkReq,cipher_supported,cert_A  from Alice  ");



		//checking talkReq=1 which means I want to talk to u
		if(talkReq!=1)
			System.out.println("Error");

		//finding the encryption and integrity protection schemes
		String[] parts = cipher_supported.split("x");
		String supported_enc= parts[0];
		String supported_int= parts[1];

		bw.write("talkReq= ");
		bw.write(talkReq);
		bw.write("\n");
		System.out.println("talkReq=  "+talkReq);

		bw.write("Encryption scheme= ");
		bw.write(supported_enc);
		bw.write("\n");
		System.out.println("Encryption scheme=  "+supported_enc);

		bw.write("Integrity Protection scheme= ");
		bw.write(supported_int);
		bw.write("\n");
		System.out.println("Integrity Protection scheme=  "+supported_int);

		bw.write("cert_A= ");
		bw.write(cert_A.toString());
		bw.write("\n");
		System.out.println("cert_A=  "+cert_A);





		//verifying cert_A
		bw.write("Bob verifying cert_A \n");
		System.out.println("Bob verifying cert_A  ");

		try{
			cert_A.checkValidity();
		}
		catch(Exception v){
			System.out.println("Certificate not valid. Exiting ......");
			//System.exit(0);
		}

		try{
			cert_A.verify(  cert_A.getPublicKey());
		}
		catch(SignatureException s){
			System.out.println("Certificate not verified. Exiting ......");
			System.exit(0);

		}

		bw.write("cert_A verified  \n");
		System.out.println("cert_A verified  ");

		//extracting Alice's public key from the certificate 
		PublicKey pubKey_Alice = cert_A.getPublicKey();

		bw.write("Extracting Alice's public key from the certificate  \n");
		System.out.println("Extracting Alice's public key from the certificate   ");



		//generating Bob certificate
		Certificates c_B = new Certificates();
		Hash_and_Encrypt eh = new Hash_and_Encrypt();

		//generating public/private key pair
		int keysize = 1024;
		CertAndKeyGen keypair= eh.generateKeyPair(keysize);

		//get the public/private key part
		PrivateKey privKey_Bob = keypair.getPrivateKey();
		PublicKey pubKey_Bob = keypair.getPublicKey();

		KeyStore ks =c_B.createCetificate("cert_B", "Bob.keystore","Bobpassword",keypair);
		X509Certificate cert_B= (X509Certificate) ks.getCertificate("cert_B");

		bw.write("Bob generating cert_B \n");
		System.out.println("Bob generating cert_B ");

		bw.write("cert_B= ");
		bw.write(cert_B.toString());
		bw.write("\n");
		System.out.println("cert_B=  "+cert_B.toString());


		//Bob sending  cert_B to Alice
		bw.write("Bob sending  cert_B to Alice \n");
		System.out.println("Bob sending  cert_B to Alice ");


		oostream_Alice.writeObject(cert_B);  
		System.out.flush();

		byte[] cert_B_b = cert_B.getEncoded();
		msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(cert_B_b)));

		//receiving encrypted_R_A
		byte [] encrypted_R_A = (byte[])oistream_Alice.readObject();  

		byte[] encrypted_R_A_b = encrypted_R_A;
		msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(encrypted_R_A_b)));

		bw.write("Bob receiving and decrypting  encrypted_R_A from Alice \n");
		System.out.println("Bob receiving and decrypting  encrypted_R_A from Alice ");

		//decrypting encrypted_R_A
		long R_A= eh.RSADecrypt(encrypted_R_A, privKey_Bob);

		bw.write("R_A= ");
		bw.write(Long.toString(R_A));
		bw.write("\n");
		System.out.println("R_A=  "+R_A);


		//generating R_B
		long R_B=Math.abs(rand.nextLong());

		bw.write("Bob generating R_B \n");
		System.out.println("Bob generating R_B ");

		bw.write("R_B= ");
		bw.write(Long.toString(R_B));
		bw.write("\n");
		System.out.println("R_B=  "+R_B);

		//Encrypting R_B

		byte [] encrypted_R_B= eh.RSAEncrypt(R_B, pubKey_Alice);

		bw.write("Bob rncrypting and sending R_B \n");
		System.out.println("Bob encrypting and sending R_B ");


		//sending encrypted_R_B
		oostream_Alice.writeObject(encrypted_R_B);

		byte[] encrypted_R_B_b = encrypted_R_B;
		msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(encrypted_R_B_b)));

		ArrayList<Byte> msg_bytes_A = new ArrayList<Byte>(msg_bytes);

		byte[] strServer = "Server".getBytes();
		msg_bytes.addAll(Arrays.asList(ArrayUtils.toObject(strServer)));

		byte [] msg=  ArrayUtils.toPrimitive(msg_bytes.toArray(new Byte[msg_bytes.size()]));

		//hashing all exchanged messages+"Server" using SHA-1
		byte [] MAC_B = eh.SHA1(msg);

		//receiving MAC_A
		byte [] MAC_A = (byte[])oistream_Alice.readObject();  

		bw.write("Bob receiving hashed MAC_A from Alice \n");
		System.out.println("Bob receiving hashed MAC_A from Alice ");

		//verifying MAC_A
		byte[] strClient = "Client".getBytes();
		msg_bytes_A.addAll(Arrays.asList(ArrayUtils.toObject(strClient)));
		byte [] msg_A=  ArrayUtils.toPrimitive(msg_bytes_A.toArray(new Byte[msg_bytes_A.size()]));
		//hashing all exchanged messages+"Client" using SHA-1
		byte [] _MAC_A = eh.SHA1(msg_A);


		bw.write("Bob verifying hashed MAC_A  \n");
		System.out.println("Bob verifying hashed MAC_A ");


		if(Arrays.equals(MAC_A, _MAC_A)){
			bw.write("Bob verified hashed MAC_A  \n");
			System.out.println("Bob verified hashed MAC_A ");
		}
		else{
			bw.write(" Hashed MAC_A not verified \n");
			System.out.println("Hashed MAC_A not verified ");

			bw.write(" Handshake phase failed at Bob \n");
			System.out.println("Handshake phase failed at Bob");
			//System.exit(0);
		}


		//Bob sending MAC_B
		bw.write("Bob sending hashed MAC_B  \n");
		System.out.println("Bob sending hashed MAC_B ");

		oostream_Alice.writeObject(MAC_B);

		//generating encryption and authentication keys
		long master_key = R_A ^ R_B;

		SecretKey enc_toAlice = eh.generateAESKey("ToAliceEncryption", master_key);
		SecretKey enc_fromAlice = eh.generateAESKey("ToBobEncryption", master_key);

		SecretKey hash_toAlice = eh.generateAESKey("ToAliceAuthentication", master_key);
		SecretKey hash_fromAlice = eh.generateAESKey("ToBobAuthentication", master_key);

		bw.write(" Bob generated required keys \n");
		System.out.println("Bob generated required keys ");

		bw.write("==============================================================================\n");
		bw.write("HandShake Phase successfully ended at Bob \n");
		bw.write("==============================================================================\n");
		System.out.println("==============================================================================\n");
		System.out.println("HandShake Phase successfully ended at Bob ");
		System.out.println("==============================================================================\n");



		bw.write("==============================================================================\n");
		bw.write("Data Exchange Phase started at Bob \n");
		bw.write("==============================================================================\n");
		System.out.println("==============================================================================\n");
		System.out.println("Data Exchange Phase started at Bob ");
		System.out.println("==============================================================================\n");

		//receiving file chunks formulated as SSL blocks
		bw.write("Bob receiving the file into chunks and reformulating these chunks into a single file \n");
		System.out.println("Bob receiving the file into chunks and reformulating these chunks into a single file ");


		FileOutputStream out = null;
		int chunklen=1024;

		try {
			out = new FileOutputStream("second_r.pdf");

			int seq=0;
			byte[] RH= new byte[8];
			byte [] tohash=new byte[1036];
			boolean eof=false;

			while(!eof){
				//receiving SSL block
				byte [] SSL_blk = (byte[])oistream_Alice.readObject();  

				//extracting record header
				RH =Arrays.copyOfRange(SSL_blk,0, 8);

				//checking RH end of file field

				if(RH[2]==1)
				{
					//end of file reached
					bw.write("Bob received all the SSL block of the file  \n");
					System.out.println("Bob received all the SSL block of the file ");
					//extracting last chunk length
					byte [] last_chunklen_b =Arrays.copyOfRange(SSL_blk,3, 7);
					ByteBuffer byteBuffer = ByteBuffer.wrap(last_chunklen_b);
					chunklen =byteBuffer.getInt(0);

					eof=true;
				}

				//extracting encrypted part	
				byte [] todecrypt =Arrays.copyOfRange(SSL_blk,8, SSL_blk.length);

				//decrypting the SSL block
				byte [] decrypted = eh.AESdecrypt(todecrypt, enc_fromAlice);

				//extracting data from SSL block
				byte [] data = Arrays.copyOfRange(decrypted,0, decrypted.length-20);

				//extracting HMAC from SSL block
				byte [] HMAC = Arrays.copyOfRange(decrypted, decrypted.length-20,decrypted.length);

				//forming the part to be hashed
				//adding seq to the part to be hashed
				byte [] seq_b= ByteBuffer.allocate(4).putInt(seq).array();
				System.arraycopy(seq_b, 0, tohash, 0, seq_b.length);

				//adding RH to the part to be hashed
				System.arraycopy(RH, 0, tohash, seq_b.length,RH.length );

				//adding data to the part to be hashed
				System.arraycopy(data, 0, tohash, seq_b.length+RH.length,data.length );

				//hashing seq,record header, data
				byte [] HMAC_r = eh.SHA1(tohash);

				//checking that HMAC equal to HMAC_r
				if (Arrays.equals(HMAC, HMAC_r))
				{
					//Integrity protection test succeeded
					//adding the data extracted to the output file
					byte [] data_towrite= new byte[chunklen];
					data_towrite=Arrays.copyOfRange(data,0, data_towrite.length);
					out.write(data_towrite);
				}
				else{
					//Integrity protection test failed
					bw.write("Integrity protection test failed at block no. : ");
					bw.write(seq);
					bw.write("\n");
					System.out.println("Integrity protection test failed at block no. : "+seq);
					System.exit(0);
				}
				seq++;

			}


			bw.write("Bob received the file  \n");
			System.out.println("Bob received the file ");



		} finally {
			if (out != null) {
				out.close();
			}

		}

		bw.write("Bob received the file from Alice \n");
		System.out.println("Bob received the file from Alice ");


		bw.write("==============================================================================\n");
		bw.write("Data exchange Phase successfully ended at Bob \n");
		bw.write("==============================================================================\n");
		System.out.println("==============================================================================\n");
		System.out.println("Data exchange Phase successfully ended at Bob ");
		System.out.println("==============================================================================\n");	






		//closing socket and streams
		ostream_Alice.close();
		istream_Alice.close();
		oostream_Alice.close();
		oistream_Alice.close();
		bw.close();
		socket.close();
	}
}
