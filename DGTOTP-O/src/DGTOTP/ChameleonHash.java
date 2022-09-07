package DGTOTP;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

public class ChameleonHash {
	
	//private key sk
	public   BigInteger sk  = null;
	//basePoint
	public static ECPoint G = null;
	//public key pk
	public  ECPoint pk = null;
	//Finite field P
	public  static BigInteger  p = null;
	//order N
	public static BigInteger N = null;

//cahmeleon hash init
public static void init() throws Exception {

	 //generate key pair
	 ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
	    KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("EC","BC");
	    keyPairGenerator.initialize(ecSpec,new SecureRandom());
	    KeyPair keyPair=keyPairGenerator.generateKeyPair();
	 //get public key
	    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
	 //curve parameter
	 N = ecPublicKey.getParameters().getN();
	//basePoint G
	 G = ecPublicKey.getParameters().getG().normalize();
	  //Finite field P
	 p = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",16);
}

//return keyPair
public  void Setup(byte[] rk) {
	this.sk = new BigInteger(1,rk).mod(N);
	this.pk = (new FixedPointCombMultiplier()).multiply(G, sk).normalize();
}

//get Randomness
public static BigInteger getRand() {
	byte[] data = new byte[32];
	SecureRandom random = new SecureRandom();
	random.nextBytes(data);
	BigInteger rand = new BigInteger(1,data);
	rand =rand.mod(p);
	return rand;
}

//eval  m1*P + r1*G
public static int eval(byte[] msg,ECPoint pk,byte[] rand) {

	BigInteger Big_msg = new BigInteger(1,msg);
	ECPoint T1 = (new FixedPointCombMultiplier()).multiply(pk, Big_msg.mod(N)).normalize();
	ECPoint T2 = (new FixedPointCombMultiplier()).multiply(G, new BigInteger(1,rand)).normalize();
	return Math.abs(T1.add(T2).normalize().hashCode());
}

//Verify
public static int Verify(byte[] msg1,byte[] r1,ECPoint pk,int CH2) {
	int result = 0;
	int CH1 = eval(msg1,pk,r1);
	if(CH1==CH2) return 1;
	return result;
}

//Collision   r2 = sk*m1 + r1 -m2*sk mod N
public static byte[] Collision(byte[] msg1,byte[] r1,byte[] msg2,BigInteger sk) {

	return sk.multiply(new BigInteger(1,msg1)).add(new BigInteger(1,r1)).subtract(sk.multiply(new BigInteger(1,msg2))).mod(N).toByteArray();

}

//ChameleonHash main()
public static void main(String[] args) throws Exception {
	
}

}

	