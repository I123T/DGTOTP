package DGTOTP;


import java.security.*;

import org.bouncycastle.crypto.digests.SHA256Digest;
public class TOTP {
	
	public static int k = Parameter.k;  //security parameter
	public static int N =Parameter.N; //the number of passwords in a TOTP instance
	public static long Δs=Parameter.Δs;//start time of a TOTP instance
	public static long Δe=Parameter.Δe;//end time of a TOTP instance
	public static  String VERIFY_POINT;//verify point
	public static String SK_SEED;//password seed
	public static SHA256Digest digest = new SHA256Digest();//Sha256
	public static byte[] sha256 = new byte[32];
	public static byte[] cache_byte = null;
		
//generate seed
public static void getSeed(String key) throws NoSuchAlgorithmException {
		String test = "testing";
		SK_SEED = byte2hex(Hash_Sha256(test));
		
	}
	
//generate password number 
public static void Setup(int k,long START_TIME,long END_TIME,long PASS_GEN) {
	 N = (int) ((END_TIME-START_TIME)/PASS_GEN);
		
	}

//TOTP init
public static String PInit(String SK_SEED) throws NoSuchAlgorithmException {
	 cache_byte = toBytes(SK_SEED);
		for(int i=1;i<=N;i++) {
			cache_byte = Hash_Sha256(cache_byte);

		}
		VERIFY_POINT = byte2hex(cache_byte);
		return byte2hex(cache_byte);
	}

//generate TOTP password
public static String PGen(String SK_SEED,long pw_sequence) throws NoSuchAlgorithmException {
		cache_byte = toBytes(SK_SEED);
		for(int i=0;i<N-pw_sequence-1;i++) {
			cache_byte = Hash_Sha256(cache_byte);
		}
	
		
		return byte2hex(cache_byte);
	}
	
//TOTP verify
public static int Verify(String VERIFY_POINT,String password,long pw_sequence) throws NoSuchAlgorithmException {
		int check_out = 0;

	cache_byte = toBytes(password);
	
		for(int i=0;i<pw_sequence+1;i++) {
			cache_byte =Hash_Sha256(cache_byte);

		}
		if(byte2hex(cache_byte).equals(VERIFY_POINT)) check_out = 1;
		return check_out;
	}
	
//Sha256
	 public static  String byte2hex(byte[] b) //二行制转字符串
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
	 
//Hex -> byte[]
public static byte[] toBytes(String str) {
	        if(str == null || str.trim().equals("")) {
	            return new byte[0];
	        }
	 
	        byte[] bytes = new byte[str.length() / 2];
	        for(int i = 0; i < str.length() / 2; i++) {
	            String subStr = str.substring(i * 2, i * 2 + 2);
	            bytes[i] = (byte) Integer.parseInt(subStr, 16);
	        }
	 
	        return bytes;

	   }

//Sha256
public static byte[] Hash_Sha256(byte[] tem) throws NoSuchAlgorithmException {
		 
		    digest.update(tem, 0, tem.length);
		    digest.doFinal(sha256, 0);
		 return sha256;
}
	 
	 public static byte[] Hash_Sha256(String message) {
		    digest.update(message.getBytes(), 0, message.getBytes().length);
		 
		    digest.doFinal(sha256, 0);
		    return sha256;
		}
	
//TOTP main()
public static void main(String[] args) throws NoSuchAlgorithmException {
		 

	

	 }
	 
}
