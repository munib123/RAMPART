# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5302_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5302_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 448-488 of the vulnerable file.

                outputlen += 6;
                if (name)
                  nlen = (unsigned char) strlen(name);
                (void) WriteBlobByte(ofile,nlen);
                outputlen++;
                for (i=0; i<nlen; i++)
                  (void) WriteBlobByte(ofile,(unsigned char) name[i]);
                outputlen += nlen;
                if ((nlen & 0x01) == 0)
                  {
                    (void) WriteBlobByte(ofile,0x00);
                    outputlen++;
                  }
                if (recnum != IPTC_ID)
                  {
                    (void) WriteBlobMSBLong(ofile, (unsigned int) len);
                    outputlen += 4;

                    next=0;
                    outputlen += len;
                    while (len--)
                      (void) WriteBlobByte(ofile,(unsigned char) token[next++]);

                    if (outputlen & 1)
                      {
                        (void) WriteBlobByte(ofile,0x00);
                        outputlen++;
                      }
                  }
                else
                  {
                    /* patch in a fake length for now and fix it later */
                    savedpos = TellBlob(ofile);
                    if (savedpos < 0)
                      return(-1);
                    (void) WriteBlobMSBLong(ofile,0xFFFFFFFFU);
                    outputlen += 4;
                    savedolen = outputlen;
                  }
              }
            else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -465,7 +465,7 @@
 
                     next=0;
                     outputlen += len;
-                    while (len--)
+                    while (len-- > 0)
                       (void) WriteBlobByte(ofile,(unsigned char) token[next++]);
 
                     if (outputlen & 1)
@@ -496,7 +496,7 @@
                     outputlen += 5;
                     next=0;
                     outputlen += len;
-                    while (len--)
+                    while (len-- > 0)
                       (void) WriteBlobByte(ofile,(unsigned char) token[next++]);
                   }
               }
```
