# CrossVul Fix Pair: 7PK in java
**Pair ID:** 4758_2
**Vulnerability Class:** 7PK
**CWE:** CWE-361
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4758_2`)

## Vulnerability Information & PoC

## Description
7PK - Time and State

## Vulnerable Code
```java
Lines 669-709 of the vulnerable file.

                    "41566E26FAEE475137EC781A0DC088A26C8804A98C23140E" +
                    "7C936281864B99571EE95C416AA38CEEBB41FDBFF1EB1D1D" +
                    "C97B63CE1355257627C8B0FD840DDB20ED35BE92F08C49AE" +
                    "A5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B", 16);

        DSAPrivateKeySpec priKey = new DSAPrivateKeySpec(
                x, dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());

        DSAPublicKeySpec pubKey = new DSAPublicKeySpec(
            y, dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());

        KeyFactory dsaKeyFact = KeyFactory.getInstance("DSA", "BC");

        doDsaTest("SHA3-" + size + "withDSA", s, dsaKeyFact, pubKey, priKey);
        doDsaTest(sigOid.getId(), s, dsaKeyFact, pubKey, priKey);
    }

    private void doDsaTest(String sigName, BigInteger s, KeyFactory ecKeyFact, DSAPublicKeySpec pubKey, DSAPrivateKeySpec priKey)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, SignatureException
    {
        SecureRandom k = new TestRandomBigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("72546832179840998877302529996971396893172522460793442785601695562409154906335")));

        byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");

        Signature dsa = Signature.getInstance(sigName, "BC");

        dsa.initSign(ecKeyFact.generatePrivate(priKey), k);

        dsa.update(M, 0, M.length);

        byte[] encSig = dsa.sign();

        ASN1Sequence sig = ASN1Sequence.getInstance(encSig);

        BigInteger r = new BigInteger("4864074fe30e6601268ee663440e4d9b703f62673419864e91e9edb0338ce510", 16);

        BigInteger sigR = ASN1Integer.getInstance(sig.getObjectAt(0)).getValue();
        if (!r.equals(sigR))
        {
            fail("r component wrong." + Strings.lineSeparator()
                + " expecting: " + r.toString(16) + Strings.lineSeparator()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -686,7 +686,9 @@
     private void doDsaTest(String sigName, BigInteger s, KeyFactory ecKeyFact, DSAPublicKeySpec pubKey, DSAPrivateKeySpec priKey)
         throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, SignatureException
     {
-        SecureRandom k = new TestRandomBigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("72546832179840998877302529996971396893172522460793442785601695562409154906335")));
+        SecureRandom k = new FixedSecureRandom(
+            new FixedSecureRandom.Source[] { new FixedSecureRandom.BigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("72546832179840998877302529996971396893172522460793442785601695562409154906335"))),
+                new FixedSecureRandom.Data(Hex.decode("01020304")) });
 
         byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");
 
```
