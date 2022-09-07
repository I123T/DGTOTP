package DGTOTP;


import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.digests.SHA256Digest;



//Merkle tree 
public class MerkleTrees {

// transaction List

 List txList;

// Merkle Root

 String root;
 public static SHA256Digest digest = new SHA256Digest();
 
//init
public MerkleTrees(List txList) {

this.txList = txList;

root = "";

}

//generate merkle tree
public void  merkle_tree() throws NoSuchAlgorithmException {

	List tempTxList = new ArrayList();

	for (int i = 0; i < this.txList.size(); i++) {

		tempTxList.add(this.txList.get(i));

	}

	List newTxList = getNewTxList(tempTxList);

	while (newTxList.size() != 1) {

		newTxList = getNewTxList(newTxList);

}

	root = (String) newTxList.get(0);

}

//get new List
private static List getNewTxList(List tempTxList) throws NoSuchAlgorithmException {

	List newTxList = new ArrayList();

	int index = 0;

	while (index < tempTxList.size()) {

// left

		String left = (String) tempTxList.get(index);

			index++;

// right

			String right = "";

			if (index != tempTxList.size()) {

				right = (String) tempTxList.get(index);

}

// sha256 hex value

			String sha2HexValue = Member.byte2hex(Parameter.Sha256(left + right));

			newTxList.add(sha2HexValue);

			index++;
}
	return newTxList;

}

//merkle verify
public static int Verify(String[]proof,String verify_point,String root,int index) {
	
	String re_root = null;
	int result=0;
	int vp_index =0;
	List proof_tem = new ArrayList();
	
	for(int i=0;i<proof.length;i++) {
		if(proof[i]=="") {
			proof[i] = verify_point;
			vp_index = i;
		
		}
		proof_tem.add(proof[i]);
	}
	
	String str = null;
	while(proof_tem !=null) {
		if(proof_tem.size()==1) break;
	if(index%2==0) {
		str = (String)proof_tem.get(vp_index) + (String)proof_tem.get(vp_index+1);
		str = Member.byte2hex(Parameter.Sha256(str));
		re_root = str;
		proof_tem.set(vp_index, str);
		proof_tem.remove(vp_index+1);

		index = index/2;
	}
	else {
		str = (String)proof_tem.get(vp_index-1) + (String)proof_tem.get(vp_index);
		str = Member.byte2hex(Parameter.Sha256(str));
		re_root = str;
		proof_tem.set(vp_index, str);
		proof_tem.remove(vp_index-1);
		vp_index = vp_index-1;
		index = index/2;
	}
		
	}
	if(str.equals(root)) result=1;

	return result;
	
}



//get  node tree 
public static String[][] get_tree(String[] vp_set) {
	String[][] tree = new String[(int) Math.ceil((Math.log(vp_set.length)/Math.log(2)))][vp_set.length];
	int length = vp_set.length;
	tree[0] = vp_set.clone();
	List hash_tem = new ArrayList();
	List level_node = new ArrayList();
	int level = 0;
	int n=0;
	for(int i=0;i<length;i++) {
		level_node.add(vp_set[i]);
		tree[0][i] = vp_set[i];
	}
	level++;
	while(n==0)
	{
		if(length==2) break;
	
	
	for(int i=0;i<length;i+=2) {
		if(i+1 !=length) 
			hash_tem.add(Member.byte2hex(Parameter.Sha256((String)level_node.get(i) + (String)level_node.get(i+1))));
		else {
			hash_tem.add(Member.byte2hex(Parameter.Sha256((String)level_node.get(i))));
		}
		
	}
	level_node.clear();
	for(int j=0;j<hash_tem.size();j++) {
		level_node.add(hash_tem.get(j));
		tree[level][j] = hash_tem.get(j).toString();
	}
	hash_tem.clear();
	length = level_node.size();
	level++;
	if(length==2) break;
	
	}
	
	return tree;
	
	
}

//get proof
public static String[] Get_Proof(String[][] tree,String node,int index) {
	
	List proof_list = new ArrayList();
	proof_list.add("");
	for(int i=0;i<tree.length;i++) {
		if(index%2==0) {
	
			proof_list.add(tree[i][index+1]);
			index  = index/2;
		}
		else {
			proof_list.add(0,tree[i][index-1]);
			index = index/2;
		}
		
	}
	String[] proof = new String[proof_list.size()];
	for(int i=0;i<proof.length;i++)
		proof[i]=(String) proof_list.get(i);
	
	return proof;
}

//get tree root
public String getRoot() {

return this.root;

}

//MerkleTrees main()
public static void main(String [] args) throws Exception {

}
}
