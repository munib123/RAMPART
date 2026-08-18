# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 4756_2
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4756_2`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 167-207 of the vulnerable file.

                throws IllegalStateException
            {
                ccm.processAADByte(in);
            }

            public void update(byte[] in, int inOff, int len)
                throws DataLengthException, IllegalStateException
            {
                ccm.processAADBytes(in, inOff, len);
            }

            public int doFinal(byte[] out, int outOff)
                throws DataLengthException, IllegalStateException
            {
                try
                {
                    return ccm.doFinal(out, 0);
                }
                catch (InvalidCipherTextException e)
                {
                    throw new IllegalStateException("exception on doFinal()", e);
                }
            }

            public void reset()
            {
                ccm.reset();
            }
        }
    }

    public static class Poly1305
        extends BaseMac
    {
        public Poly1305()
        {
            super(new org.bouncycastle.crypto.macs.Poly1305(new AESEngine()));
        }
    }

    public static class Poly1305KeyGen
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -184,7 +184,7 @@
                 }
                 catch (InvalidCipherTextException e)
                 {
-                    throw new IllegalStateException("exception on doFinal()", e);
+                    throw new IllegalStateException("exception on doFinal(): " + e.toString());
                 }
             }
 
```
