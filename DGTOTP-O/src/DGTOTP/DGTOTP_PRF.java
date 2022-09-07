package DGTOTP;

import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DGTOTP_PRF {

	public static Cipher cipher = null;

//return keyPair
public static SecretKey createKey() throws Exception {
 
		try {
			Security.addProvider(new BouncyCastleProvider());
			// generate key
			KeyGenerator keyGenerator;
			keyGenerator = KeyGenerator.getInstance("AES","BC");
			keyGenerator.init(128);
			SecretKey secretKey = keyGenerator.generateKey();

	            return secretKey;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
 
	}
	
//AES enc
public static byte[] jdkAES(String context, SecretKey originalKey) {
		try {
				
			Parameter.AesCipher.init(Parameter.AesCipher.ENCRYPT_MODE, originalKey);
	
			return 	Parameter.AesCipher.doFinal(context.getBytes());

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

//AES enc
public static byte[] ksAES(String context, Cipher cipher)throws Exception {
		
		return cipher.doFinal(context.getBytes());
	}

//AES enc
public static byte[] keAES(String context, Cipher cipher)throws Exception {		
			return cipher.doFinal(context.getBytes());
		}
	
//AES enc
public static byte[] kvAES(String context, Cipher cipher)throws Exception {
			return cipher.doFinal(context.getBytes());
		}

//AES enc
public static byte[] krAES(String context, Cipher cipher)throws Exception {
		
			return cipher.doFinal(context.getBytes());
	
		}
		
//AES dec
public static byte[] decrypt(byte[] result, SecretKey originalKey) {
		
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			
			cipher.init(Cipher.DECRYPT_MODE, (java.security.Key) originalKey);
			result = cipher.doFinal(result);
		  return result;
		} catch (Exception e) {
			e.printStackTrace();
		}
 return null;
	
	}
}
