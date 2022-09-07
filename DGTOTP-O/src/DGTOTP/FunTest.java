package DGTOTP;

import java.math.BigInteger;
import java.security.Security;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

//test function
public class FunTest {

//test
public static void test() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		 RA ra = new RA(); //instantiate the class RA
		//test the function RASetup
		 RA.RASetup(128);
		 System.out.println("---RASetup execution information---");
		 System.out.println("The number of passwords in a TOTP instance:%d".formatted(Parameter.N));
		 System.out.println("The number of TOTP protocol instances:%d".formatted(Parameter.E));
		 System.out.println("Verify epoch:%d (ms)".formatted(Parameter.¦¤e));
		 System.out.println("Password generate epoch:%d (ms)".formatted(Parameter.¦¤s));
		 System.out.println("Group public key:"+ra.gpk);
		 System.out.println("---RASetup runs successfully---"+"\n");

		//instantiate the class Member
		Member[] member = new Member[Parameter.U];
		for(int i=0;i<Parameter.U;i++)
			member[i] = new Member();
		
		//generate random ID 
		Random random = new Random();
		//byte[] ID
		byte[] id = new byte[8];
		random.nextBytes(id);
		//String ID
		String ID = Member.byte2hex(id);
		
		//test the function PInit
		//member[0] runs the PInit
		member[0].PInit(ID);
		System.out.println("---PInit execution information---");
		System.out.println("Member ID:%s".formatted(member[0].ID_MENBER));
		System.out.println("Initialization key of member:%s".formatted(member[0].SECRET_KEY.toString()));
		System.out.println("---Member '%s' PInit runs successfully---".formatted(member[0].ID_MENBER)+"\n");
		//current time
		long current_time = System.currentTimeMillis();
	
		// test the function Join
		byte[][] Ax=ra.Join(ra.Key_RA,ID,current_time);
		System.out.println("---Join execution information---");
		System.out.println("ID of the join member:%s".formatted(member[0].ID_MENBER));
		System.out.println("Ks of the join member:%s".formatted(Ax[0].toString()));
		System.out.println("Alpha ID of the join member:%d".formatted(Parameter.bytesToInt(Ax[1])));
		System.out.println("---Member '%s' Join runs successfully---".formatted(member[0].ID_MENBER)+"\n");
		
		//test the function PwGen
		//generate DGTOTP password of member[0]
		String[] password = member[0].PwGen(Ax, current_time); //run the function PwGen
		System.out.println("---DGTOTP password information---");
		System.out.println("TOTP password: %s".formatted(password[0]));
		System.out.println("Chameleon Hash collision: %s".formatted(String.valueOf(new BigInteger(password[1].getBytes("ISO-8859-1")))));
		System.out.println("Identity ciphertext: %s".formatted(Member.byte2hex(password[2].getBytes("ISO-8859-1"))));
		System.out.println("---Member '%s' PwGen runs successfully---".formatted(member[0].ID_MENBER)+"\n");
		
		//test the function GMUpdate
		ra.GMUpdate(Parameter.START_TIME);
		System.out.println("---GMUpdate execution information---");
		System.out.println("Member identity ciphertext set is updated");
		System.out.println("Chameleon Hash public key set is updated");
		System.out.println("Chameleon Hash set V of the current verify epoch is updated");
		System.out.println("---GMUpdate runs successfully---"+"\n");
		
		//test Verify 
		//Verify member[0] password for correct password and time
		System.out.println("---Verify result of the password of the member '%s'---".formatted(member[0].ID_MENBER));
		System.out.println("Verify result for the correct password and verify epoch:%d".formatted(Verifier.Verify(password, current_time))); 
		//Verify member[0] password for correct password but wrong time
		System.out.println("Verify result for the correct password but the wrong verify epoch:%d".formatted(Verifier.Verify(password, current_time+Parameter.¦¤e))); 
		System.out.println("---Verify runs successfully---"+"\n");
		
		//test Open member[0] ID
		//Open member[0] ID for correct password and time
		System.out.println("---Open result of the password of the member '%s'---".formatted(member[0].ID_MENBER));
		System.out.println("Open ID for the correct password and verify epoch: "+RA.Open(password, current_time));
		//Open member[0] ID for false password and time
		System.out.println("Open ID for the correct password but the wrong verify epoch: "+RA.Open(password, current_time+Parameter.¦¤e));
		System.out.println("---Open runs successfully---"+"\n");
		
		//test Revoke ID "Member"
		System.out.println("---Revoke result of the member---");
		//revoke registered member
		System.out.println("The result of revoke registered member");
		if(RA.Revoke(ID, ra.Key_RA)==1)
		System.out.println("Revoke registered member '%s' successfully-----".formatted(member[0].ID_MENBER));
		//revoke unregistered member
		System.out.println("The result of revoke unregistered member");
		if(RA.Revoke("two", ra.Key_RA)==0)
		 System.out.println("Failed to revoke member '%s',this member is not registered with RA-----".formatted("two"));
		System.out.println("---Revoke runs successfully---"+"\n");
	}
	
public static void main(String[] args) throws Exception {
	//call test function
	test();
	
}
	
}
