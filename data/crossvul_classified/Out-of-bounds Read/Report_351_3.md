# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 647-688 of the vulnerable file.

			/* don't crash on bad data */
			if (val_len < len) {
				len = val_len;
			}
			/* if we run out of return space, truncate */
			if (tlv_len < len) {
				len = tlv_len;
			}
			memcpy(tlv_ptr, val_ptr, len);
		}
		break;

	case CAC_OBJECT_TYPE_CERT:
		/* read file */
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
			 " obj= cert_file, val_len=%"SC_FORMAT_LEN_SIZE_T"u (0x%04"SC_FORMAT_LEN_SIZE_T"x)",
			 val_len, val_len);
		cert_len = 0;
		cert_ptr = NULL;
		cert_type = 0;
		for (tl_ptr = tl, val_ptr=val; tl_len >= 2;
				val_len -= len, val_ptr += len, tl_len -= tl_head_len) {
			tl_start = tl_ptr;
			if (sc_simpletlv_read_tag(&tl_ptr, tl_len, &tag, &len) != SC_SUCCESS)
				break;
			tl_head_len = tl_ptr - tl_start;
			if (tag == CAC_TAG_CERTIFICATE) {
				cert_len = len;
				cert_ptr = val_ptr;
			}
			if (tag == CAC_TAG_CERTINFO) {
				if ((len >= 1) && (val_len >=1)) {
					cert_type = *val_ptr;
				}
			}
			if (tag == CAC_TAG_MSCUID) {
				sc_log_hex(card->ctx, "MSCUID", val_ptr, len);
			}
			if ((val_len < len) || (tl_len < tl_head_len)) {
				break;
			}
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -664,12 +664,17 @@
 		cert_len = 0;
 		cert_ptr = NULL;
 		cert_type = 0;
-		for (tl_ptr = tl, val_ptr=val; tl_len >= 2;
-				val_len -= len, val_ptr += len, tl_len -= tl_head_len) {
+		for (tl_ptr = tl, val_ptr = val; tl_len >= 2;
+		    val_len -= len, val_ptr += len, tl_len -= tl_head_len) {
 			tl_start = tl_ptr;
 			if (sc_simpletlv_read_tag(&tl_ptr, tl_len, &tag, &len) != SC_SUCCESS)
 				break;
 			tl_head_len = tl_ptr - tl_start;
+
+			/* incomplete value */
+			if (val_len < len)
+				break;
+
 			if (tag == CAC_TAG_CERTIFICATE) {
 				cert_len = len;
 				cert_ptr = val_ptr;
```
