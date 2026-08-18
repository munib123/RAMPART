# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 42_9
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `42_9`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 34-74 of the vulnerable file.

    public BCXMSSPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        XMSSKeyParams keyParams = XMSSKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
        this.treeDigest = keyParams.getTreeDigest().getAlgorithm();

        XMSSPrivateKey xmssPrivateKey = XMSSPrivateKey.getInstance(keyInfo.parsePrivateKey());

        try
        {
            XMSSPrivateKeyParameters.Builder keyBuilder = new XMSSPrivateKeyParameters
                .Builder(new XMSSParameters(keyParams.getHeight(), DigestUtil.getDigest(treeDigest)))
                .withIndex(xmssPrivateKey.getIndex())
                .withSecretKeySeed(xmssPrivateKey.getSecretKeySeed())
                .withSecretKeyPRF(xmssPrivateKey.getSecretKeyPRF())
                .withPublicSeed(xmssPrivateKey.getPublicSeed())
                .withRoot(xmssPrivateKey.getRoot());

            if (xmssPrivateKey.getBdsState() != null)
            {
                keyBuilder.withBDSState((BDS)XMSSUtil.deserialize(xmssPrivateKey.getBdsState()));
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
        return "XMSS";
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
@@ -51,7 +51,7 @@
 
             if (xmssPrivateKey.getBdsState() != null)
             {
-                keyBuilder.withBDSState((BDS)XMSSUtil.deserialize(xmssPrivateKey.getBdsState()));
+                keyBuilder.withBDSState((BDS)XMSSUtil.deserialize(xmssPrivateKey.getBdsState(), BDS.class));
             }
 
             this.keyParams = keyBuilder.build();
```
