# CrossVul Fix Pair: 7PK in java
**Pair ID:** 4758_1
**Vulnerability Class:** 7PK
**CWE:** CWE-361
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4758_1`)

## Vulnerability Information & PoC

## Description
7PK - Time and State

## Vulnerable Code
```java
Lines 27-67 of the vulnerable file.

import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;
import org.bouncycastle.util.test.TestRandomData;

/**
 * Test based on FIPS 186-2, Appendix 5, an example of DSA, and FIPS 168-3 test vectors.
 */
public class DSATest
    extends SimpleTest
{
    byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
    byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

    SecureRandom    random = new FixedSecureRandom(
        new FixedSecureRandom.Source[] { new FixedSecureRandom.Data(k1), new FixedSecureRandom.Data(k2) });

    byte[] keyData = Hex.decode("b5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
    
    SecureRandom    keyRandom = new FixedSecureRandom(
                      new FixedSecureRandom.Source[] { new FixedSecureRandom.Data(keyData), new FixedSecureRandom.Data(keyData) });

    BigInteger  pValue = new BigInteger("8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291", 16);
    BigInteger  qValue = new BigInteger("c773218c737ec8ee993b4f2ded30f48edace915f", 16);

    public String getName()
    {
        return "DSA";
    }

    public void performTest()
    {
        BigInteger              r = new BigInteger("68076202252361894315274692543577577550894681403");
        BigInteger              s = new BigInteger("1089214853334067536215539335472893651470583479365");
        DSAParametersGenerator  pGen = new DSAParametersGenerator();

        pGen.init(512, 80, random);

        DSAParameters           params = pGen.generateParameters();
        DSAValidationParameters pValid = params.getValidationParameters();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,7 +44,7 @@
     byte[] keyData = Hex.decode("b5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
     
     SecureRandom    keyRandom = new FixedSecureRandom(
-                      new FixedSecureRandom.Source[] { new FixedSecureRandom.Data(keyData), new FixedSecureRandom.Data(keyData) });
+                      new FixedSecureRandom.Source[] { new FixedSecureRandom.Data(keyData), new FixedSecureRandom.Data(keyData), new FixedSecureRandom.Data(Hex.decode("01020304"))});
 
     BigInteger  pValue = new BigInteger("8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291", 16);
     BigInteger  qValue = new BigInteger("c773218c737ec8ee993b4f2ded30f48edace915f", 16);
@@ -165,7 +165,11 @@
                     "A5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B", 16);
 
         DSAPrivateKeyParameters priKey = new DSAPrivateKeyParameters(x, dsaParams);
-        SecureRandom k = new TestRandomBigInteger("72546832179840998877302529996971396893172522460793442785601695562409154906335");
+        SecureRandom k = new FixedSecureRandom(
+            new FixedSecureRandom.Source[] {
+                new FixedSecureRandom.BigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("72546832179840998877302529996971396893172522460793442785601695562409154906335"))),
+                new FixedSecureRandom.Data(Hex.decode("01020304"))
+            });
 
         byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");
 
@@ -287,7 +291,10 @@
 
         DSASigner signer = new DSASigner();
 
-        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new TestRandomBigInteger("349C55648DCF992F3F33E8026CFAC87C1D2BA075", 16)));
+        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new FixedSecureRandom(
+            new FixedSecureRandom.Source[] {
+                new FixedSecureRandom.BigInteger("349C55648DCF992F3F33E8026CFAC87C1D2BA075"),
+                new FixedSecureRandom.Data(Hex.decode("01020304")) })));
 
         byte[] msg = Hex.decode("A9993E364706816ABA3E25717850C26C9CD0D89D");
 
@@ -404,7 +411,11 @@
 
             DSASigner signer = new DSASigner();
 
-            signer.init(true, new ParametersWithRandom(kp.getPrivate(), new TestRandomData(Hex.decode("735959CC4463B8B440E407EECA8A473BF6A6D1FE657546F67D401F05"))));
+            signer.init(true, new ParametersWithRandom(kp.getPrivate(), new FixedSecureRandom(
+                new FixedSecureRandom.Source[] {
+                    new FixedSecureRandom.BigInteger(Hex.decode("735959CC4463B8B440E407EECA8A473BF6A6D1FE657546F67D401F05")),
+                    new FixedSecureRandom.Data(Hex.decode("01020304"))
+                })));
 
             byte[] msg = Hex.decode("23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7");
 
@@ -520,7 +531,11 @@
 
         DSASigner signer = new DSASigner();
 
-        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new TestRandomData(Hex.decode("0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C"))));
+        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new FixedSecureRandom(
+            new FixedSecureRandom.Source[] {
+                new FixedSecureRandom.BigInteger(Hex.decode("0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C")),
+                new FixedSecureRandom.Data(Hex.decode("01020304"))
+            })));
 
         byte[] msg = Hex.decode("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
 
@@ -651,7 +666,10 @@
 
         DSASigner signer = new DSASigner();
 
-        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new TestRandomData(Hex.decode("A6902C1E6E3943C5628061588A8B007BCCEA91DBF12915483F04B24AB0678BEE"))));
+        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new FixedSecureRandom(
+            new FixedSecureRandom.Source[]
+                { new FixedSecureRandom.BigInteger("A6902C1E6E3943C5628061588A8B007BCCEA91DBF12915483F04B24AB0678BEE"),
+                  new FixedSecureRandom.Data(Hex.decode("01020304")) })));
 
         byte[] msg = Hex.decode("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
 
```
