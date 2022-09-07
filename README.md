# DGTOTP 
# General prerequisites <br>
For compilation, you need to download the following <br>

-Java 17: https://www.oracle.com/java/technologies/downloads/#jdk17-windows <br>

-Eclipse 2021-12: https://www.eclipse.org/downloads/packages/release /2021-12/ <br>

-Bouncy Castle Crypto APIs (bcprov-jdk15to18): https://www.bouncycastle.org/ latest_ releases.html <br>

# Code structure <br>
-RA.java includes the implementation of algorithms: RASetup, Join, Revoke, Open, and Verify. <br>

-Member.java mainly contains the algorithms: PInit, GetSD and PwGen. <br>

-Parameter.java are written for parameter initialization. <br>

-ChameleonHash.java contains the chameleon hash functions. <br>

-MerkleTrees.java contains the merkle tree functions. <br>

-TOTP.java implements the TOTP scheme required in this paper. <br>

# How to run <br>
You can instantiate the FunTest class to run the test function, which has the following main steps: <br>

-Instantiate the class RA, and run the function RASetup to complete the RA initialization. <br>

-Instantiate the class Member to create a group member, and run the function Pinit to get its TOTP secret key kt. <br>

-Call the Join function of the RA instance to enroll a group member and generate its secret key ks. <br>

-Call the PwGen function of the group member instance to generate a password. <br>

-Call the GMUpdate function of the RA instance to generate the group management messages for the current verify epoch. <br>

-Call the Verify function of the Verifier class to verify the password generated by a group member instance.	<br>

-(optional) Call Open and Revoke function of the RA instance to open the identity and revoke a group member, respectively. <br>
