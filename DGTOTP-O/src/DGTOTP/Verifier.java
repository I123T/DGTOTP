package DGTOTP;

import java.util.Arrays;

public class Verifier {
	public static int current_verify_epoch=(int) ((System.currentTimeMillis()-Parameter.START_TIME)/Parameter.¦¤e);//current verify epoch
	public static String verifier_root=null;//root of sub-tree of current verify epoch 
	
	public static String[][] sub_tree = new String[(int) Math.ceil((Math.log(Parameter.U)/Math.log(2)))][Parameter.U];//merkle tree

	//Verify	
public static int  Verify(String[] password,long time)throws Exception {
		//a certain verify epoch
	     int verify_peoch_index = (int) ((time-Parameter.START_TIME)/Parameter.¦¤e);
	     if(current_verify_epoch!=verify_peoch_index) return 0;
	     //get password index
	    int pw_index = (int) ((time-verify_peoch_index*Parameter.¦¤e-Parameter.START_TIME)/Parameter.¦¤s);
		//initialization of verify result
	    int result = 0;
		//permuted index of  identity ciphertext
		int index = 0;
		byte[] cache_tem = TOTP.toBytes(password[0]);
			for(int i=0;i<pw_index+1;i++) {
				cache_tem =Parameter.Sha256( cache_tem);
			}
		//get verify point of TOTP
		String vp = Member.byte2hex(cache_tem);
		//vp'
		byte[] verify_point = Parameter.Sha256(vp+password[2]+verify_peoch_index);
		for(int j=0;j<Parameter.U;j++) {
			if( Parameter.Member_cipher[j].equals(password[2])) {
				index = j;
				break;
			}
		 }
		//chameleon hash 
		int ch_dvp = ChameleonHash.eval(verify_point, Parameter.CH_key[index], password[1].getBytes("ISO-8859-1"));
		String[] ch_hash = new String[Parameter.U];
		//get chameleon hash value set(String)
		 for(int i=0;i<Parameter.U;i++) {
			 ch_hash[i] = String.valueOf(Parameter.CH_hash[i]);
		 }
		//compute merkle proof
		 if(verifier_root==null) {
		sub_tree = MerkleTrees.get_tree(ch_hash);
		MerkleTrees merkleTree = new MerkleTrees(Arrays.asList(ch_hash));
		merkleTree.merkle_tree();
       verifier_root = merkleTree.getRoot();
		 }
		 //get merkle proof of the verify point(vp') 
		String[] verifier_mp = MerkleTrees.Get_Proof(sub_tree, String.valueOf(ch_dvp), index);
		//Merkle.Verify && TOTP.Verify
		if(MerkleTrees.Verify(Parameter.merkle_proof, verifier_root, Parameter.gpk,verify_peoch_index)==1
				&& TOTP.Verify(vp, password[0], pw_index)==1 
				)  {
			return 1;
		}
		return result;
	}

	
}
