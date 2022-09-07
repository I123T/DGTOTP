package DGTOTP;

import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;


public class RA {
	

	public static int U = 0;   //the number of group members
	public static int k=0;//security parameter
	public static int  N = 0;//the number of passwords in a TOTP instance
	public static int E;//the number of TOTP protocol instances
	public static long START_TIME = 0; //start time
	public static long END_TIME = 0;//end time
	public static int Δe=0;//verify epoch 
	public static int Δs=0;//password generate epoch
	public static Random KEY_PERMUTATION;//permutation key
	public static SecretKey Key_RA =null;//secret key of the RA
	public static String[][] merkle_proof = null;//merkle proof of the sub-tree root
	public static String[][] CH_hash = null;//chamemleon hash value
	public static String[][] ch_hash = null;//permutated chameleon hash value
	public static byte[] dvp = null;//dummy verify point
	public static byte[] rd = null;//rand
	public static String[] SMT = null;//sub-Merkle trees SMT
	public static String  gpk = null;//group public key
	public static List[] per_table = null;//E permutation set
	public static String[][] sub_tree = null;//merkle tree
	public static byte[] rk = null;//chameleon hash sk
	public static String[] IDLG = null; //storing the identities of registered group members
	public static byte[] RL = null; //Revocation List
	public static int verify_epoch = 0;//a certain verify epoch
	public static int per_id_index = 0;//cache the permutated id index
	public static int byte_size = 32;//32 bytes 
	public static int alpha = 0;//the index of the member join
	public static byte[] cache_tem = null;//byte[] data
	public static byte[][] ID_byte_cipher = null;//Member ID cipher
	public static Cipher ks_cipher = null;//RA key cipher
	public static String G = null;//group instance G
	public static int current_verify_epoch=0;//current verify epoch

//RA.Setup
public static void RASetup(int security_parameter) throws Exception {	
	    k= security_parameter;
		//chameleon hash setup
		ChameleonHash.init();
		//parameter initialization
		Parameter.init();
		G = Parameter.G;
		START_TIME = Parameter.START_TIME;
		Δe=Parameter.Δe;
		END_TIME = Parameter.END_TIME;
		Δs=Parameter.Δs;
		N = Parameter.N;	
		E = Parameter.E;
		U = Parameter.U;
		SMT = new String[E];  //E merkle tree root
		merkle_proof = new String[E][];
		per_table = new List[E];
		sub_tree = new String[(int) Math.ceil((Math.log(U)/Math.log(2)))][U];
		ID_byte_cipher = new byte[U][];
		rk = new byte[byte_size];
	    dvp = new byte[byte_size];
	    rd = new byte[byte_size];
	    ch_hash = new String[E][U];
	    CH_hash = new String[E][U];
		//revocation list
		RL = new byte[U];
		//identities list of registered group members
		IDLG = new String[U];
		
		//generate secret key of RA
		KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
		 keyGen.init(k);
		 Key_RA = keyGen.generateKey();
		//RA_ASE key cipher initial
		ks_cipher =Cipher.getInstance("AES/ECB/PKCS5Padding");
		ks_cipher.init(ks_cipher.ENCRYPT_MODE, Key_RA);
		
		//Initialize ks of the member 
		SecretKey	Member_ks = null;
		 for(int j=0;j<U;j++){
			 if(RL[j]==1) continue;//if member is revoked
			 //generate ks
			 cache_tem = DGTOTP_PRF.ksAES(G+"KS"+j, ks_cipher);
			 Member_ks = new SecretKeySpec(cache_tem, "AES");
			
			for(int i=0;i<E;i++) {
				//dummy verify points
				dvp = Parameter.byteMerger(DGTOTP_PRF.jdkAES(G+"DVP"+i,  Member_ks), DGTOTP_PRF.jdkAES(G+"DVP"+i,  Member_ks));
				//rand
				rd = Parameter.byteMerger(DGTOTP_PRF.jdkAES(G+"DR"+i,  Member_ks), DGTOTP_PRF.jdkAES(G+"DR"+i,  Member_ks));
				//generate chameleon hash keys
				rk = Parameter.byteMerger(DGTOTP_PRF.jdkAES(G+"CHR"+i,  Member_ks),DGTOTP_PRF.jdkAES(G+"CHR"+i,  Member_ks));
				Parameter.chame_hash.Setup(rk);
				//generate shuffled  merkle sub-tree node
				CH_hash[i][j] = String.valueOf(ChameleonHash.eval(dvp,Parameter.chame_hash.pk,rd));
			}
		 }
		//permutate the chamemleon hash value	 
		 for(int i=0;i<E;i++) {
			 //generate permuted set
			 cache_tem = DGTOTP_PRF.ksAES(G+"PM"+i, ks_cipher);
			 Random PM_seed = new Random();
			 PM_seed.setSeed(cache_tem.hashCode());
			 per_table[i] = Permutation(PM_seed);
			 //permutate the chameleon hash value
			 for(int j=0;j<U;j++) {
				 ch_hash[i][(int) per_table[i].get(j)] = CH_hash[i][j];
			 }
			 
			//generate E Merkle tree for chameleon hash value
			 List<String> asList = Arrays.asList(ch_hash[i]);
				MerkleTrees  merkle_tree = new MerkleTrees(asList);
				merkle_tree.merkle_tree();
				SMT[i] = merkle_tree.getRoot();	
		 }

		//	generate merkle proof of tree contains sub-tree root
		String[][] root_tree = MerkleTrees.get_tree(SMT);
		for(int i=0;i<E;i++) {
			merkle_proof[i] = MerkleTrees.Get_Proof(root_tree, SMT[i],i);
		}
		//group public key 
		List<String> asList = Arrays.asList(SMT);
		MerkleTrees  merkle_tree = new MerkleTrees(asList);
		merkle_tree.merkle_tree();
		gpk = merkle_tree.getRoot();
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

//generated permuted set
public static List Permutation(Random random) {
		List list = new ArrayList();
		for(int i=0;i<U;i++) {
			list.add(i);
		}
		//use random 
		Collections.shuffle(list,random);
		return list;
	}
	
//update the group management message
public  void GMUpdate(long time) throws Exception{

		int instance_index = (int) ((time-START_TIME)/Δe);
		//V
	    int[] V = new int[U];
		int[] per_V = new int[U];
		//Chameleon Hash public key
		ECPoint[] public_key = new ECPoint[U];
		ECPoint[] per_public_key = new ECPoint[U];
		SecretKey ks = null;
		byte[] dvp = new byte[byte_size];
		byte[] rd = new byte[byte_size];
		byte[] rk = new byte[byte_size];
		SecretKey ke = null;
		byte[] re = new byte[16];
		String[] ciphertext = new String[U];
		String[] per_ciphertext = new String[U];
		//compute U member identity ciphertext
		for(int i=0;i<U;i++)
		{
			 cache_tem = DGTOTP_PRF.ksAES(G+"KS"+i, ks_cipher);
			 ks = new SecretKeySpec(cache_tem, "AES");
				//dummy vp
				dvp = Parameter.byteMerger(DGTOTP_PRF.jdkAES(G+"DVP"+instance_index,  ks), DGTOTP_PRF.jdkAES(G+"DVP"+instance_index, ks));
				rd = Parameter.byteMerger(DGTOTP_PRF.jdkAES(G+"DR"+instance_index,  ks), DGTOTP_PRF.jdkAES(G+"DR"+instance_index, ks));
				rk = Parameter.byteMerger(DGTOTP_PRF.jdkAES(G+"CHR"+instance_index,  ks),DGTOTP_PRF.jdkAES(G+"CHR"+instance_index,  ks));
				//chameleon hash setup
				Parameter.chame_hash.Setup(rk);
			    public_key[i] = Parameter.chame_hash.pk;
				//chameleon hash eval 
				V[i] = ChameleonHash.eval(dvp,Parameter.chame_hash.pk,rd);
				//compute ID cipher
				ke = new SecretKeySpec(DGTOTP_PRF.jdkAES("KeyGen"+instance_index, ks), "AES");
				re = DGTOTP_PRF.jdkAES("Rand"+instance_index, ks);
				//ASEe
				ID_byte_cipher[i]= ASE_enc(intToBytes(i),ke,re);
				ciphertext[i] = new String(ID_byte_cipher[i],"ISO-8859-1");
		}
		//permutation
		 cache_tem = DGTOTP_PRF.ksAES(G+"PM"+instance_index, ks_cipher);
		 Random PM_seed = new Random();
		 PM_seed.setSeed(cache_tem.hashCode());
		// KEY_PERMUTATION = PM_seed;
		 per_table[instance_index] = Permutation(PM_seed);
		
			for(int i=0;i<U;i++) {
				per_V[i] = V[(int) per_table[instance_index].get(i)];
				per_ciphertext[i] = ciphertext[(int) per_table[instance_index].get(i)];
				per_public_key[i] = public_key[(int) per_table[instance_index].get(i)];
			}
		//publish group management message
			String[] proof = merkle_proof[instance_index];
			//length of the proof
			Parameter.proof_len = proof.length;
			//sub-tree root proof
			Parameter.merkle_proof = proof.clone();
			//sub-tree node
			Parameter.CH_hash = per_V.clone();
			//ID cipher 
			Parameter.Member_cipher = per_ciphertext.clone();
			//chameleon hash public key
			Parameter.CH_key=  per_public_key.clone();
			//gpk key
			Parameter.gpk = gpk;
	
			MerkleTrees.Verify(Parameter.merkle_proof, SMT[instance_index], 
					SMT[instance_index],instance_index);

	}
//Open Member ID
public static String Open(String[] password,long time)throws Exception {
	//Get Id Index of the permuted MPI
	per_id_index = 0;
	for(int j=0;j<U;j++) {
		if( Parameter.Member_cipher[j].equals(password[2])) {
			per_id_index = j;
			break;
		}
	 }
	verify_epoch =(int) ((time-START_TIME)/Δe);
	current_verify_epoch=(int) ((System.currentTimeMillis()-Parameter.START_TIME)/Parameter.Δe);
	if(verify_epoch!=current_verify_epoch) return null;
	long pw_sequence = (time-verify_epoch*Δe-START_TIME)/Δs;
	//get TOTP verify point(byte[])
	cache_tem = TOTP.toBytes(password[0]);

		for(int i=0;i<pw_sequence+1;i++) {
			cache_tem =Parameter.Sha256( cache_tem);
		}
		//TOTP verify point(String)
		String vp = Member.byte2hex(cache_tem);
		cache_tem = Parameter.Sha256(vp+password[2]+verify_epoch);
		//"ISO-8859-1" string -> byte[] chameleon hash eval
	int vp_point = ChameleonHash.eval(cache_tem,Parameter.CH_key[(int) per_table[verify_epoch].get(per_id_index)], password[1].getBytes("ISO-8859-1"));
	
	//permutation
	 cache_tem = DGTOTP_PRF.ksAES(G+"PM"+verify_epoch, ks_cipher);
	 Random PM_seed = new Random();
	 PM_seed.setSeed(cache_tem.hashCode());
	 List regen_per_table = Permutation(PM_seed);
  
		//TOTP.verify && Merkle.verify
	if(MerkleTrees.Verify(Parameter.merkle_proof, SMT[verify_epoch], Parameter.gpk,verify_epoch)==1 && TOTP.Verify(vp, password[0], pw_sequence)==1 )  {
		int ID_plain = 0;
		cache_tem = DGTOTP_PRF.ksAES(G+"KS"+per_table[verify_epoch].get(per_id_index), ks_cipher);
		SecretKey ks = new SecretKeySpec(cache_tem, "AES");
		cache_tem = DGTOTP_PRF.jdkAES("KeyGen"+verify_epoch, ks);
		SecretKey ke = new SecretKeySpec(cache_tem, "AES");
		
		//dec the identity ciphertext
		ID_plain  = Parameter.bytesToInt(ASE_dec(ke,Parameter.Member_cipher[per_id_index].getBytes("ISO-8859-1"),DGTOTP_PRF.jdkAES("Rand"+verify_epoch, ks)));
		return IDLG[ID_plain];
	} 
	 return null;
}

//ASE enc
public static byte[] ASE_enc(byte[] data,SecretKey key,byte[] assocData) throws Exception {
		Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", "BC");
	    enc.init(Cipher.ENCRYPT_MODE, key, 
		 new AEADParameterSpec(Parameter.nonce, 96, assocData));
		 return enc.doFinal(data); 
	}

//ASE dec 
public static byte[] ASE_dec(SecretKey key,byte[] data,byte[] assocData)throws Exception {
		Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", "BC"); 
		dec.init(Cipher.DECRYPT_MODE, key, 
		 new AEADParameterSpec(Parameter.nonce, 96, assocData));
		 return dec.doFinal(data);
	}

// Member Join
public  byte[][] Join(SecretKey ks,String ID,long time)throws Exception {
		
			byte[][] Ax = new byte[2][];
		
	    	//Ks byte[]
			IDLG[alpha] = ID;
		   Ax[0] = DGTOTP_PRF.ksAES(G+"KS"+alpha, ks_cipher);
		   //alpha ID index byte[]
		   Ax[1] = intToBytes(alpha);
		   alpha++;
		   return Ax;
	}

//Revoke
 public static int Revoke(String ID,SecretKey RA_key)throws Exception	{
	 per_id_index = 0;
	int result =0;
	 for(int i=0;i<IDLG.length;i++) {
		 if(IDLG[i]==ID) {per_id_index = i;
		 result=1;
		 break;
		 }
	 }
	 RL[per_id_index] = 1;
	 return result;
	 
 }
 
 
 //RA main()
public static void main(String[] args) throws Exception {
	
	}

}
