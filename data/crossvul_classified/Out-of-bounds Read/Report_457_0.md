# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 457_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `457_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1241-1279 of the vulnerable file.

            uint32_t csum = (uint32_t) -1;

            if ((meta_id & ID_ODD_SIZE) || meta_bc < 2 || meta_bc > 4)
                return FALSE;

#ifdef BITSTREAM_SHORTS
            while (wcount--)
                csum = (csum * 3) + *csptr++;
#else
            WavpackNativeToLittleEndian ((WavpackHeader *) buffer, WavpackHeaderFormat);

            while (wcount--) {
                csum = (csum * 3) + csptr [0] + (csptr [1] << 8);
                csptr += 2;
            }

            WavpackLittleEndianToNative ((WavpackHeader *) buffer, WavpackHeaderFormat);
#endif

            if (meta_bc == 4) {
                if (*dp++ != (csum & 0xff) || *dp++ != ((csum >> 8) & 0xff) || *dp++ != ((csum >> 16) & 0xff) || *dp++ != ((csum >> 24) & 0xff))
                    return FALSE;
            }
            else {
                csum ^= csum >> 16;

                if (*dp++ != (csum & 0xff) || *dp++ != ((csum >> 8) & 0xff))
                    return FALSE;
            }

            checksum_passed++;
        }

        bcount -= meta_bc;
        dp += meta_bc;
    }

    return (bcount == 0) && (!verify_checksum || !(wphdr->flags & HAS_CHECKSUM) || checksum_passed);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1258,13 +1258,13 @@
 #endif
 
             if (meta_bc == 4) {
-                if (*dp++ != (csum & 0xff) || *dp++ != ((csum >> 8) & 0xff) || *dp++ != ((csum >> 16) & 0xff) || *dp++ != ((csum >> 24) & 0xff))
+                if (*dp != (csum & 0xff) || dp[1] != ((csum >> 8) & 0xff) || dp[2] != ((csum >> 16) & 0xff) || dp[3] != ((csum >> 24) & 0xff))
                     return FALSE;
             }
             else {
                 csum ^= csum >> 16;
 
-                if (*dp++ != (csum & 0xff) || *dp++ != ((csum >> 8) & 0xff))
+                if (*dp != (csum & 0xff) || dp[1] != ((csum >> 8) & 0xff))
                     return FALSE;
             }
 
```
