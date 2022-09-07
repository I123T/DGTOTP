package DGTOTP;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;



public class Member {
	//	public static String ID_MENBER ;
	public String ID_MENBER ; //Member ID
	public static  byte[] alpha;//transformed identity of ID
	public  SecretKey SECRET_KEY;//key kt
	public static int k=0;//security parameter
	public static int  N= 0;//the number of passwords in a TOTP instance
	public static int E; //the number of TOTP protocol instances
	public static long START_TIME;//start time
	public static long END_TIME;//end time
	public static int ¦¤s=0;//password generate epoch
	public static int ¦¤e=0;//verify epoch
	public  String SECRET_SEED; //secret seed sd
	public String cipher_id;//identity ciphertext
	public byte[] cache_byte = null;//caches the current variable 16bytes
	public  byte[] cache_32 = new byte[32];//caches the current variable 32bytes
	public String cache_string = null;//caches the current variable String
	public SecretKey ks = null; //secret key ks
	public Cipher ks_cipher = null;//the Cipher of secret key ks
	public Cipher key_cipher = null;//the Cipher of secret key kt
	public ChameleonHash chame_hash = null;//Instantiate the class chameleonHash
	public byte[] rand = new byte[32]; //the chameleon hash collision
	


	
//Member initial
public  void  PInit(String ID) throws Exception {
		//parameter initial
		START_TIME = Parameter.START_TIME;
		END_TIME = Parameter.END_TIME;
		E = Parameter.E;
		N = Parameter.N;
		k = Parameter.k;
		¦¤s = Parameter.¦¤s;
		¦¤e = Parameter.¦¤e;
		this.SECRET_KEY = null;
		//generate secret key
		 KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
         keyGen.init(128);
         SECRET_KEY = keyGen.generateKey();
         //init Cipher
         key_cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
         key_cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY);

		ID_MENBER = ID;
	}

// get the password seed of the current verify epoch 
public  byte[] GetSD(SecretKey SECRET_KEY,long time)throws Exception {
		int chain_index =  (int) ((time-START_TIME)/¦¤e);
		return Parameter.byteMerger(DGTOTP_PRF.ksAES(ID_MENBER+chain_index,key_cipher),DGTOTP_PRF.ksAES(ID_MENBER+chain_index,key_cipher));
	}

//generate password 
public  String[] PwGen(byte[][] Ax,long time) throws Exception {
		//DGTOTP password
		String[] DGTOTP_pw = new String [3];
		int instance_index = (int) ((time - START_TIME)/¦¤e);
		
		if(SECRET_SEED!=null) cache_string = SECRET_SEED;
		else {
			cache_string = Member.byte2hex(GetSD(SECRET_KEY,time));
			SECRET_SEED = cache_string;
		}
		//password index z
		long pw_sequence = (time-instance_index*¦¤e-START_TIME)/¦¤s;
		//TOTP password 
		cache_string = TOTP.PGen(cache_string, pw_sequence);
		DGTOTP_pw[0] = cache_string;
		
		// Mmeber cache chameleon hash collision and identity ciphertext
		if(rand!=null && cipher_id!=null) {
			 DGTOTP_pw[2] = cipher_id;
			 DGTOTP_pw[1] = new String(rand, "ISO-8859-1");
			 return DGTOTP_pw;	
		}
	    //member ks
		ks = new SecretKeySpec(Ax[0], "AES");
		ks_cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		ks_cipher.init(ks_cipher.ENCRYPT_MODE, ks);
		//ke encryption key
		cache_byte = DGTOTP_PRF.ksAES("KeyGen"+instance_index, ks_cipher);
		SecretKey ke = new SecretKeySpec(cache_byte, "AES");
		 // genrate re
		 cache_byte = DGTOTP_PRF.ksAES("Rand"+instance_index, ks_cipher);
		//transformed identity of ID
		 alpha = Ax[1];
		//identity ciphertext
		 cache_byte = RA.ASE_enc(Ax[1], ke, cache_byte);
		 DGTOTP_pw[2] = new String(cache_byte, "ISO-8859-1");
		 cipher_id = DGTOTP_pw[2];
		 //chameleon hash sk
		 cache_32 = Parameter.byteMerger(DGTOTP_PRF.ksAES(Parameter.G+"CHR"+instance_index, ks_cipher),
				 DGTOTP_PRF.ksAES(Parameter.G+"CHR"+instance_index, ks_cipher));
		 //get verify point 
		 byte[] cache_tem = TOTP.toBytes(DGTOTP_pw[0]);
				for(int i=0;i<pw_sequence+1;i++) {
					cache_tem =Parameter.Sha256( cache_tem);
				}
				//get verify point of TOTP
				String vp = Member.byte2hex(cache_tem);
		
		 //vp'
		 byte[] verify_point = Parameter.Sha256(vp+DGTOTP_pw[2]+instance_index);
		 //dummy verify point
		byte[] dvp = Parameter.byteMerger(DGTOTP_PRF.ksAES(Parameter.G+"DVP"+instance_index, ks_cipher),
				DGTOTP_PRF.ksAES(Parameter.G+"DVP"+instance_index, ks_cipher));
		//rand
		byte[] rd = Parameter.byteMerger(DGTOTP_PRF.ksAES(Parameter.G+"DR"+instance_index, ks_cipher), 
				DGTOTP_PRF.ksAES(Parameter.G+"DR"+instance_index, ks_cipher));
		//chameleon hash collision
		byte[] r = ChameleonHash.Collision(dvp,rd,verify_point,new BigInteger(1,cache_32).mod(Parameter.chame_hash.N));
		rand = r;
		//byte[] -> String ISO-8859-1
		DGTOTP_pw[1] = new String(r, "ISO-8859-1"); //rand
		return DGTOTP_pw;
	}

//byte[] -> String(hexadecimal)
 public static  String byte2hex(byte[] b) 
		{
		 String hs="";
		 String stmp="";
		 for (int n=0;n<b.length;n++)
		  {
		   stmp=(java.lang.Integer.toHexString(b[n] & 0XFF));
		   if (stmp.length()==1) hs=hs+"0"+stmp;
		   else hs=hs+stmp;
		   if (n<b.length-1)  hs=hs+"";
		  }
		 return hs.toUpperCase();
		}

 //Member main()	 
public static void main(String[] args) throws Exception {
	
         
	 }
	 
	 
}
