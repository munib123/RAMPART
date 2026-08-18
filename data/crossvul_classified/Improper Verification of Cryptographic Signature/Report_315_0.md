# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in c
**Pair ID:** 315_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `315_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```c
Lines 140-172 of the vulnerable file.

	pfree(temp_s.ptr);
	mpz_clear(&c);
    }

    /* check signature contents */
    /* verify padding (not including any DER digest info! */
    padlen = sig_len - 3 - hash_len;
    /* now check padding */

    DBG(DBG_CRYPT,
	DBG_dump("verify_sh decrypted SIG1:", s, sig_len));
    DBG(DBG_CRYPT, DBG_log("pad_len calculated: %d hash_len: %d", padlen, (int)hash_len));

    /* skip padding */
    if(s[0]    != 0x00
       || s[1] != 0x01
       || s[padlen+2] != 0x00) {
	return "3""SIG padding does not check out";
    }

    s += padlen + 3;
    (*psig) = s;

    /* return SUCCESS */
    return NULL;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -157,8 +157,21 @@
 	return "3""SIG padding does not check out";
     }
 
-    s += padlen + 3;
-    (*psig) = s;
+    /* signature starts after ASN wrapped padding [00,01,FF..FF,00] */
+    (*psig) = s + padlen + 3;
+
+    /* verify padding contents */
+    {
+        const u_char *p;
+        size_t cnt_ffs = 0;
+
+        for (p = s+2; p < s+padlen+2; p++)
+            if (*p == 0xFF)
+                cnt_ffs ++;
+
+        if (cnt_ffs != padlen)
+            return "4" "invalid Padding String";
+    }
 
     /* return SUCCESS */
     return NULL;
```
