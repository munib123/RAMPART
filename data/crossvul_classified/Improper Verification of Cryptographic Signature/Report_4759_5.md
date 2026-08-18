# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in java
**Pair ID:** 4759_5
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4759_5`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```java
Lines 126-166 of the vulnerable file.

    // signature malleability was a problem: https://en.bitcoin.it/wiki/Transaction_Malleability
    static final String[] MODIFIED_SIGNATURES  = {
        "303e02811c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9e"
        + "f41dd424a4e1c8f16967cf3365813fe8786236",
        "303f0282001c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f"
        + "9ef41dd424a4e1c8f16967cf3365813fe8786236",
        "303e021d001e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9e"
        + "f41dd424a4e1c8f16967cf3365813fe8786236",
        "303e021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd02811d00ade65988d237d30f9e"
        + "f41dd424a4e1c8f16967cf3365813fe8786236",
        "303f021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd0282001d00ade65988d237d30f"
        + "9ef41dd424a4e1c8f16967cf3365813fe8786236",
        "303e021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021e0000ade65988d237d30f9e"
        + "f41dd424a4e1c8f16967cf3365813fe8786236",
        "30813d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9e"
        + "f41dd424a4e1c8f16967cf3365813fe8786236",
        "3082003d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f"
        + "9ef41dd424a4e1c8f16967cf3365813fe8786236",
        "303d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9ef4"
        + "1dd424a4e1c8f16967cf3365813fe87862360000",
        "3040021c57b10411b54ab248af03d8f2456676ebc6d3db5f1081492ac87e9ca8021d00942b117051d7d9d107fc42cac9c5a36a1fd7f0f8916ccca86cec4ed3040100"
    };

    private void testModified()
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("DSA", "BC");
        PublicKey pubKey = kFact.generatePublic(PUBLIC_KEY);
        Signature sig = Signature.getInstance("DSA", "BC");

        for (int i = 0; i != MODIFIED_SIGNATURES.length; i++)
        {
            sig.initVerify(pubKey);

            sig.update(Strings.toByteArray("Hello"));

            boolean failed;

            try
            {
                failed = !sig.verify(Hex.decode(MODIFIED_SIGNATURES[i]));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -143,7 +143,8 @@
         + "9ef41dd424a4e1c8f16967cf3365813fe8786236",
         "303d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9ef4"
         + "1dd424a4e1c8f16967cf3365813fe87862360000",
-        "3040021c57b10411b54ab248af03d8f2456676ebc6d3db5f1081492ac87e9ca8021d00942b117051d7d9d107fc42cac9c5a36a1fd7f0f8916ccca86cec4ed3040100"
+        "3040021c57b10411b54ab248af03d8f2456676ebc6d3db5f1081492ac87e9ca8021d00942b117051d7d9d107fc42cac9c5a36a1fd7f0f8916ccca86cec4ed3040100",
+        "303e021c57b10411b54ab248af03d8f2456676ebc6d3db5f1081492ac87e9ca802811d00942b117051d7d9d107fc42cac9c5a36a1fd7f0f8916ccca86cec4ed3"
     };
 
     private void testModified()
```
