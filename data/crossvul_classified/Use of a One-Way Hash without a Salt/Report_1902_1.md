# CrossVul Fix Pair: Use of a One-Way Hash without a Salt in java
**Pair ID:** 1902_1
**Vulnerability Class:** Use of a One-Way Hash without a Salt
**CWE:** CWE-759
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1902_1`)

## Vulnerability Information & PoC

## Description
Use of a One-Way Hash without a Salt - This makes it easier for attackers to pre-compute the hash value using dictionary attack techniques such as rainbow tables.

## Vulnerable Code
```java
Lines 1-23 of the vulnerable file.

package com.bijay.onlinevotingsystem.controller;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256 {

	public String getSHA(String password) {

		try {
			// Static getInstance method is called with hashing SHA
			MessageDigest md = MessageDigest.getInstance("SHA-256");

			// digest() method called
			// to calculate message digest of an input
			// and return array of byte
			byte[] messageDigest = md.digest(password.getBytes());

			// Convert byte array into signum representation
			BigInteger no = new BigInteger(1, messageDigest);

			// Convert message digest into hex value
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,32 +1,21 @@
 package com.bijay.onlinevotingsystem.controller;
 
-import java.math.BigInteger;
 import java.security.MessageDigest;
 import java.security.NoSuchAlgorithmException;
+import java.security.SecureRandom;
+import java.util.Base64;
 
 public class SHA256 {
+	private static final String SSHA_PREFIX = "{SSHA}";
+	private static final int SSHA_256_LENGTH = 32; // SHA-256 is 32 bytes long
+	private static final int SALT_LENGTH = 16; // Use a 16 byte salt
 
 	public String getSHA(String password) {
-
 		try {
-			// Static getInstance method is called with hashing SHA
-			MessageDigest md = MessageDigest.getInstance("SHA-256");
-
-			// digest() method called
-			// to calculate message digest of an input
-			// and return array of byte
-			byte[] messageDigest = md.digest(password.getBytes());
-
-			// Convert byte array into signum representation
-			BigInteger no = new BigInteger(1, messageDigest);
-
-			// Convert message digest into hex value
-			String hashPass = no.toString(16);
-
-			while (hashPass.length() < 32) {
-				hashPass = "0" + hashPass;
-			}
-			return hashPass;
+			byte[] salt = getSalt();
+			String cipher = getCipher(password, salt);
+			
+			return cipher;
 
 			// For specifying wrong message digest algorithms
 		} catch (NoSuchAlgorithmException e) {
@@ -34,4 +23,54 @@
 			return null;
 		}
 	}
+
+	public static boolean validatePassword(String password, String cipherText) {
+		boolean isValid = false;
+		try {
+			String cipher = cipherText.substring(SSHA_PREFIX.length());
+		
+			byte[] cipherBytes = Base64.getDecoder().decode(cipher.getBytes());
+			byte[] salt = new byte[SALT_LENGTH];
+			System.arraycopy(cipherBytes, SSHA_256_LENGTH, salt, 0, SALT_LENGTH);
+
+			String result = getCipher(password, salt);
+			//Compare the newly hashed password taking the same salt with the input hash
+			isValid = result.equals(cipherText);
+		} catch (NoSuchAlgorithmException e) {
+			e.printStackTrace();
+		}
+		return isValid;
+	}
+	
+	private static byte[] getSalt() throws NoSuchAlgorithmException {
+		SecureRandom random = new SecureRandom();
+		byte[] salt = new byte[SALT_LENGTH];
+		random.nextBytes(salt);
+		return salt;
+	}
+
+	private static String getCipher(String password, byte[] salt) throws NoSuchAlgorithmException {
+		// Static getInstance method is called with hashing SHA
+		MessageDigest md = MessageDigest.getInstance("SHA-256");
+		md.update(salt);
+	
+		byte[] passBytes = password.getBytes();
+		byte[] allBytes = new byte[passBytes.length + SALT_LENGTH];
+		System.arraycopy(passBytes, 0, allBytes, 0, passBytes.length);
+		System.arraycopy(salt, 0, allBytes, passBytes.length, SALT_LENGTH);
+	
+			
+		byte[] cipherBytes = new byte[SSHA_256_LENGTH + SALT_LENGTH];
+			
+		// digest() method called
+		// to calculate message digest of an input
+		// and return array of byte
+		byte[] messageDigest = md.digest(allBytes);
+	
+		System.arraycopy(messageDigest, 0, cipherBytes, 0, SSHA_256_LENGTH);
+		System.arraycopy(salt, 0, cipherBytes, SSHA_256_LENGTH, SALT_LENGTH);
+		
+		String result = SSHA_PREFIX + Base64.getEncoder().encodeToString(cipherBytes);
+		return result;
+	}
 }
```
