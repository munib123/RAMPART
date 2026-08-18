# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 740_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `740_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2194-2234 of the vulnerable file.

        PString[i] = (unsigned char) c;
      }
      PString[ plen ] = 0;
      if ((plen & 0x01) == 0)
      {
        c=ReadBlobByte(ifile);
        if (c == EOF)
          {
            PString=(unsigned char *) RelinquishMagickMemory(PString);
            return -1;
          }
      }
    }
    count=(ssize_t) ReadBlobMSBSignedLong(ifile);
    if ((count < 0) || (count > GetBlobSize(ifile)))
      {
        PString=(unsigned char *) RelinquishMagickMemory(PString);
        return -1;
      }
    /* make a buffer to hold the data and snag it from the input stream */
    str=(unsigned char *) AcquireQuantumMemory((size_t) count,sizeof(*str));
    if (str == (unsigned char *) NULL)
      {
        PString=(unsigned char *) RelinquishMagickMemory(PString);
        return 0;
      }
    for (i=0; i < (ssize_t) count; i++)
    {
      c=ReadBlobByte(ifile);
      if (c == EOF)
        {
          str=(unsigned char *) RelinquishMagickMemory(str);
          PString=(unsigned char *) RelinquishMagickMemory(PString);
          return -1;
        }
      str[i]=(unsigned char) c;
    }

    /* we currently skip thumbnails, since it does not make
     * any sense preserving them in a real world application
     */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2211,7 +2211,7 @@
         return -1;
       }
     /* make a buffer to hold the data and snag it from the input stream */
-    str=(unsigned char *) AcquireQuantumMemory((size_t) count,sizeof(*str));
+    str=(unsigned char *) AcquireQuantumMemory((size_t) count+1,sizeof(*str));
     if (str == (unsigned char *) NULL)
       {
         PString=(unsigned char *) RelinquishMagickMemory(PString);
```
