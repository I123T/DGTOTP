# DGTOTP 
# General prerequisites <br>
For compilation, you need to download the following <br>
-Java 17: https://www.oracle.com/java/technologies/downloads/#jdk17-windows <br>
-Eclipse 2021-12: https://www.eclipse.org/downloads/packages/release /2021-12/ <br>
-Bouncy Castle Crypto APIs (bcprov-jdk15to18): https://www.bouncycastle.org/ latest_ releases.html <br>

# Code Structure <br>
-RA.java includes the implementation of algorithms: RASetup, Join, Revoke, Open, and Verify. <br>
-Member.java mainly contains the algorithms: PInit, GetSD and PwGen. <br>
-Parameter.java are written for parameter initialization. <br>
-ChameleonHash.java contains the chameleon hash functions. <br>
-MerkleTrees.java contains the merkle tree functions. <br>
-TOTP.java implements the TOTP scheme required in this paper. <br>
