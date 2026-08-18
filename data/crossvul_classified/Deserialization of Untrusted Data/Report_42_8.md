# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 42_8
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `42_8`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 35-75 of the vulnerable file.

    public BCXMSSMTPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
        this.treeDigest = keyParams.getTreeDigest().getAlgorithm();

        XMSSPrivateKey xmssMtPrivateKey = XMSSPrivateKey.getInstance(keyInfo.parsePrivateKey());

        try
        {
            XMSSMTPrivateKeyParameters.Builder keyBuilder = new XMSSMTPrivateKeyParameters
                .Builder(new XMSSMTParameters(keyParams.getHeight(), keyParams.getLayers(), DigestUtil.getDigest(treeDigest)))
                .withIndex(xmssMtPrivateKey.getIndex())
                .withSecretKeySeed(xmssMtPrivateKey.getSecretKeySeed())
                .withSecretKeyPRF(xmssMtPrivateKey.getSecretKeyPRF())
                .withPublicSeed(xmssMtPrivateKey.getPublicSeed())
                .withRoot(xmssMtPrivateKey.getRoot());

            if (xmssMtPrivateKey.getBdsState() != null)
            {
                keyBuilder.withBDSState((BDSStateMap)XMSSUtil.deserialize(xmssMtPrivateKey.getBdsState()));
            }

            this.keyParams = keyBuilder.build();
        }
        catch (ClassNotFoundException e)
        {
            throw new IOException("ClassNotFoundException processing BDS state: " + e.getMessage());
        }
    }

    public String getAlgorithm()
    {
        return "XMSSMT";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,7 +52,7 @@
 
             if (xmssMtPrivateKey.getBdsState() != null)
             {
-                keyBuilder.withBDSState((BDSStateMap)XMSSUtil.deserialize(xmssMtPrivateKey.getBdsState()));
+                keyBuilder.withBDSState((BDSStateMap)XMSSUtil.deserialize(xmssMtPrivateKey.getBdsState(), BDSStateMap.class));
             }
 
             this.keyParams = keyBuilder.build();
```
