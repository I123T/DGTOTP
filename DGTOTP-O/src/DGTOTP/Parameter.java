package DGTOTP;


import java.security.Security;
import javax.crypto.Cipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
//Pameter init Class
public class Parameter {
	public static int U = 0;   //the number of group members
	public static int k=128;//security parameter
	public static int  N = 60;//the number of passwords in a TOTP instance
	public static int E=0;//the number of TOTP protocol instances
	public static long START_TIME = 0; //start time
	public static long END_TIME = 0;//end time
	public static int ¦¤e=300000;//verify epoch 
	public static int ¦¤s=5000;//password generate epoch
	public static ChameleonHash chame_hash = null;//instantiation class ChameleonHash
	public static SHA256Digest digest = null;//Sha256
	public static String G = null;//group instance G
	public static Cipher AesCipher = null;//AES cipher
	public static  byte[] nonce = null;//ASE-GCM nonce
	public static  int[] CH_hash=null;//V
	public static String[] Member_cipher = null;//member identity ciphertext
	public static ECPoint[] CH_key = null;//chameleon hash pk
	public static String[] merkle_proof = null;//merkle proof
	public static int proof_len = 0;//proof length
	public static String gpk = null;//group public key
	
//init parameter
public static void init() throws Exception{
	
		Security.addProvider(new BouncyCastleProvider());
		G = "DGTOTP";
		//AES-GCM
		chame_hash  =new ChameleonHash();
		ChameleonHash.init();
		E = 100;
		U = 100;
		START_TIME = System.currentTimeMillis();
		END_TIME  = START_TIME + E*¦¤e;     
		N = 60;
		digest = new SHA256Digest();
		Member_cipher = new String[U];
		CH_key = new ECPoint[U];
		CH_hash = new int[U];
		merkle_proof = new String[proof_len];
		nonce = "202122232425262728292a2b2c".getBytes();
		//AES
		AesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		
	}

//Sha256
public static byte[] Sha256(byte[] message) {
		byte[]	sha256Bytes = new byte[32];
	    digest.update(message, 0, message.length);
	 
	    digest.doFinal(sha256Bytes, 0);
	    return sha256Bytes;
	}

//Sha256
public static byte[] Sha256(String message) {
		byte[]	sha256Bytes = new byte[32];
	    digest.update(message.getBytes(), 0, message.getBytes().length);
	    digest.doFinal(sha256Bytes, 0);
	    return sha256Bytes;
	}

//byte[] -> int
public static int bytesToInt(byte[] bytes) {
		int i;
		i = (int) ((bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8)
				| ((bytes[2] & 0xff) << 16) | ((bytes[3] & 0xff) << 24));
		return i;
	}
//byte[] + byte[]
public static byte[] byteMerger(byte[] byte_1, byte[] byte_2){  
	        byte[] byte_3 = new byte[byte_1.length+byte_2.length];  
	        System.arraycopy(byte_1, 0, byte_3, 0, byte_1.length);  
	        System.arraycopy(byte_2, 0, byte_3, byte_1.length, byte_2.length);  
	        return byte_3;  
	 }  

//int to byte[]
public static byte[] intToBytes(int i) {
			byte[] bytes = new byte[4];
			bytes[0] = (byte) (i & 0xff);
			bytes[1] = (byte) ((i >> 8) & 0xff);
			bytes[2] = (byte) ((i >> 16) & 0xff);
			bytes[3] = (byte) ((i >> 24) & 0xff);
			return bytes;
		}

}
