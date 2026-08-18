# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 42_3
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `42_3`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 69-109 of the vulnerable file.

				throw new ParseException("private key has wrong size", 0);
			}
			*/
            int position = 0;
            int index = Pack.bigEndianToInt(privateKey, position);
            if (!XMSSUtil.isIndexValid(height, index))
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
            BDS bdsImport = null;
            try
            {
                bdsImport = (BDS)XMSSUtil.deserialize(bdsStateBinary);
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
            bdsImport.validate();
            if (bdsImport.getIndex() != index)
            {
                throw new IllegalStateException("serialized BDS has wrong index");
            }
            bdsState = bdsImport;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,26 +86,25 @@
             position += rootSize;
 			/* import BDS state */
             byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(privateKey, position, privateKey.length - position);
-            BDS bdsImport = null;
             try
             {
-                bdsImport = (BDS)XMSSUtil.deserialize(bdsStateBinary);
+                BDS bdsImport = (BDS)XMSSUtil.deserialize(bdsStateBinary, BDS.class);
+                bdsImport.setXMSS(builder.xmss);
+                bdsImport.validate();
+                if (bdsImport.getIndex() != index)
+                {
+                    throw new IllegalStateException("serialized BDS has wrong index");
+                }
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
-            bdsImport.validate();
-            if (bdsImport.getIndex() != index)
-            {
-                throw new IllegalStateException("serialized BDS has wrong index");
-            }
-            bdsState = bdsImport;
+                throw new IllegalArgumentException(e.getMessage(), e);
+            }
         }
         else
         {
```
