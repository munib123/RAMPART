# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in java
**Pair ID:** 4754_1
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4754_1`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```java
Lines 52-92 of the vulnerable file.

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;
import org.bouncycastle.util.test.TestRandomData;

public class DSATest
    extends SimpleTest
{
    byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
    byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

    SecureRandom    random = new FixedSecureRandom(new byte[][] { k1, k2 });

    private void testCompat()
        throws Exception
    {
        if (Security.getProvider("SUN") == null)
        {
            return;
        }

        Signature           s = Signature.getInstance("DSA", "SUN");
        KeyPairGenerator    g = KeyPairGenerator.getInstance("DSA", "SUN");
        byte[]              data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
        
        g.initialize(512, new SecureRandom());
        
        KeyPair p = g.generateKeyPair();
        
        PrivateKey  sKey = p.getPrivate();
        PublicKey   vKey = p.getPublic();
        
        //
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,6 +70,110 @@
 
     SecureRandom    random = new FixedSecureRandom(new byte[][] { k1, k2 });
 
+    // DSA modified signatures, courtesy of the Google security team
+    static final DSAPrivateKeySpec PRIVATE_KEY = new DSAPrivateKeySpec(
+        // x
+        new BigInteger(
+            "15382583218386677486843706921635237927801862255437148328980464126979"),
+        // p
+        new BigInteger(
+            "181118486631420055711787706248812146965913392568235070235446058914"
+            + "1170708161715231951918020125044061516370042605439640379530343556"
+            + "4101919053459832890139496933938670005799610981765220283775567361"
+            + "4836626483403394052203488713085936276470766894079318754834062443"
+            + "1033792580942743268186462355159813630244169054658542719322425431"
+            + "4088256212718983105131138772434658820375111735710449331518776858"
+            + "7867938758654181244292694091187568128410190746310049564097068770"
+            + "8161261634790060655580211122402292101772553741704724263582994973"
+            + "9109274666495826205002104010355456981211025738812433088757102520"
+            + "562459649777989718122219159982614304359"),
+        // q
+        new BigInteger(
+            "19689526866605154788513693571065914024068069442724893395618704484701"),
+        // g
+        new BigInteger(
+            "2859278237642201956931085611015389087970918161297522023542900348"
+            + "0877180630984239764282523693409675060100542360520959501692726128"
+            + "3149190229583566074777557293475747419473934711587072321756053067"
+            + "2532404847508798651915566434553729839971841903983916294692452760"
+            + "2490198571084091890169933809199002313226100830607842692992570749"
+            + "0504363602970812128803790973955960534785317485341020833424202774"
+            + "0275688698461842637641566056165699733710043802697192696426360843"
+            + "1736206792141319514001488556117408586108219135730880594044593648"
+            + "9237302749293603778933701187571075920849848690861126195402696457"
+            + "4111219599568903257472567764789616958430"));
+
+    static final DSAPublicKeySpec PUBLIC_KEY = new DSAPublicKeySpec(
+        new BigInteger(
+            "3846308446317351758462473207111709291533523711306097971550086650"
+            + "2577333637930103311673872185522385807498738696446063139653693222"
+            + "3528823234976869516765207838304932337200968476150071617737755913"
+            + "3181601169463467065599372409821150709457431511200322947508290005"
+            + "1780020974429072640276810306302799924668893998032630777409440831"
+            + "4314588994475223696460940116068336991199969153649625334724122468"
+            + "7497038281983541563359385775312520539189474547346202842754393945"
+            + "8755803223951078082197762886933401284142487322057236814878262166"
+            + "5072306622943221607031324846468109901964841479558565694763440972"
+            + "5447389416166053148132419345627682740529"),
+         PRIVATE_KEY.getP(),
+         PRIVATE_KEY.getQ(),
+         PRIVATE_KEY.getG());
+
+    // The following test vectors check for signature malleability and bugs. That means the test
+    // vectors are derived from a valid signature by modifying the ASN encoding. A correct
+    // implementation of DSA should only accept correct DER encoding and properly handle the others.
+    // Allowing alternative BER encodings is in many cases benign. An example where this kind of
+    // signature malleability was a problem: https://en.bitcoin.it/wiki/Transaction_Malleability
+    static final String[] MODIFIED_SIGNATURES  = {
+        "303e02811c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9e"
+        + "f41dd424a4e1c8f16967cf3365813fe8786236",
+        "303f0282001c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f"
+        + "9ef41dd424a4e1c8f16967cf3365813fe8786236",
+        "303e021d001e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9e"
+        + "f41dd424a4e1c8f16967cf3365813fe8786236",
+        "303e021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd02811d00ade65988d237d30f9e"
+        + "f41dd424a4e1c8f16967cf3365813fe8786236",
+        "303f021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd0282001d00ade65988d237d30f"
+        + "9ef41dd424a4e1c8f16967cf3365813fe8786236",
+        "303e021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021e0000ade65988d237d30f9e"
+        + "f41dd424a4e1c8f16967cf3365813fe8786236",
+        "30813d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9e"
+        + "f41dd424a4e1c8f16967cf3365813fe8786236",
+        "3082003d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f"
+        + "9ef41dd424a4e1c8f16967cf3365813fe8786236",
+        "303d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9ef4"
+        + "1dd424a4e1c8f16967cf3365813fe87862360000",
+        "3040021c57b10411b54ab248af03d8f2456676ebc6d3db5f1081492ac87e9ca8021d00942b117051d7d9d107fc42cac9c5a36a1fd7f0f8916ccca86cec4ed3040100"
+    };
+
+    private void testModified()
+        throws Exception
+    {
+        KeyFactory kFact = KeyFactory.getInstance("DSA", "BC");
+        PublicKey pubKey = kFact.generatePublic(PUBLIC_KEY);
+        Signature sig = Signature.getInstance("DSA", "BC");
+
+        for (int i = 0; i != MODIFIED_SIGNATURES.length; i++)
+        {
+            sig.initVerify(pubKey);
+
+            sig.update(Strings.toByteArray("Hello"));
+
+            boolean failed;
+
+            try
+            {
+                failed = !sig.verify(Hex.decode(MODIFIED_SIGNATURES[i]));
+            }
+            catch (SignatureException e)
+            {
+                failed = true;
+            }
+
+            isTrue("sig verified when shouldn't", failed);
+        }
+    }
+
     private void testCompat()
         throws Exception
     {
@@ -1223,6 +1327,7 @@
         testDSA2Parameters();
         testNullParameters();
         testValidate();
+        testModified();
     }
 
     protected BigInteger[] derDecode(
```
