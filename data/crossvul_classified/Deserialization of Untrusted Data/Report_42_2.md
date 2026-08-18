# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 42_2
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `42_2`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 51-91 of the vulnerable file.

			}
			*/
            int position = 0;
            index = XMSSUtil.bytesToXBigEndian(privateKey, position, indexSize);
            if (!XMSSUtil.isIndexValid(totalHeight, index))
            {
                throw new IllegalArgumentException("index out of bounds");
            }
            position += indexSize;
            secretKeySeed = XMSSUtil.extractBytesAtOffset(privateKey, position, secretKeySize);
            position += secretKeySize;
            secretKeyPRF = XMSSUtil.extractBytesAtOffset(privateKey, position, secretKeyPRFSize);
            position += secretKeyPRFSize;
            publicSeed = XMSSUtil.extractBytesAtOffset(privateKey, position, publicSeedSize);
            position += publicSeedSize;
            root = XMSSUtil.extractBytesAtOffset(privateKey, position, rootSize);
            position += rootSize;
			/* import BDS state */
            byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(privateKey, position, privateKey.length - position);

            BDSStateMap bdsImport = null;
            try
            {
                bdsImport = (BDSStateMap)XMSSUtil.deserialize(bdsStateBinary);
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
            catch (ClassNotFoundException e)
            {
                e.printStackTrace();
            }
            bdsImport.setXMSS(builder.xmss);
            bdsState = bdsImport;
        }
        else
        {
			/* set */
            index = builder.index;
            byte[] tmpSecretKeySeed = builder.secretKeySeed;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,21 +68,21 @@
 			/* import BDS state */
             byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(privateKey, position, privateKey.length - position);
 
-            BDSStateMap bdsImport = null;
             try
             {
-                bdsImport = (BDSStateMap)XMSSUtil.deserialize(bdsStateBinary);
+                BDSStateMap bdsImport = (BDSStateMap)XMSSUtil.deserialize(bdsStateBinary, BDSStateMap.class);
+
+                bdsImport.setXMSS(builder.xmss);
+                bdsState = bdsImport;
             }
             catch (IOException e)
             {
-                e.printStackTrace();
+                throw new IllegalArgumentException(e.getMessage(), e);
             }
             catch (ClassNotFoundException e)
             {
-                e.printStackTrace();
-            }
-            bdsImport.setXMSS(builder.xmss);
-            bdsState = bdsImport;
+                throw new IllegalArgumentException(e.getMessage(), e);
+            }
         }
         else
         {
@@ -260,17 +260,14 @@
 		/* copy root */
         XMSSUtil.copyBytesAtOffset(out, root, position);
 		/* concatenate bdsState */
-        byte[] bdsStateOut = null;
         try
         {
-            bdsStateOut = XMSSUtil.serialize(bdsState);
+            return Arrays.concatenate(out, XMSSUtil.serialize(bdsState));
         }
         catch (IOException e)
         {
-            e.printStackTrace();
-            throw new RuntimeException("error serializing bds state");
-        }
-        return Arrays.concatenate(out, bdsStateOut);
+            throw new IllegalStateException("error serializing bds state: " + e.getMessage(), e);
+        }
     }
 
     public long getIndex()
```
