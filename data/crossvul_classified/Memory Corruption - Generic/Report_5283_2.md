# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5283_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5283_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1592-1632 of the vulnerable file.

				EVP_MD_CTX_cleanup(&md_ctx);

				if (error) {
					spprintf(error, 0, "broken openssl signature");
				}

				return FAILURE;
			}

			EVP_MD_CTX_cleanup(&md_ctx);
#endif

			*signature_len = phar_hex_str((const char*)sig, sig_len, signature);
		}
		break;
#ifdef PHAR_HASH_OK
		case PHAR_SIG_SHA512: {
			unsigned char digest[64];
			PHP_SHA512_CTX context;

			PHP_SHA512Init(&context);
			read_len = end_of_phar;

			if (read_len > sizeof(buf)) {
				read_size = sizeof(buf);
			} else {
				read_size = (int)read_len;
			}

			while ((len = php_stream_read(fp, (char*)buf, read_size)) > 0) {
				PHP_SHA512Update(&context, buf, len);
				read_len -= (zend_off_t)len;
				if (read_len < read_size) {
					read_size = (int)read_len;
				}
			}

			PHP_SHA512Final(digest, &context);

			if (memcmp(digest, sig, sizeof(digest))) {
				if (error) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1609,6 +1609,13 @@
 			unsigned char digest[64];
 			PHP_SHA512_CTX context;
 
+			if (sig_len < sizeof(digest)) {
+				if (error) {
+					spprintf(error, 0, "broken signature");
+				}
+				return FAILURE;
+			}
+
 			PHP_SHA512Init(&context);
 			read_len = end_of_phar;
 
@@ -1642,6 +1649,13 @@
 			unsigned char digest[32];
 			PHP_SHA256_CTX context;
 
+			if (sig_len < sizeof(digest)) {
+				if (error) {
+					spprintf(error, 0, "broken signature");
+				}
+				return FAILURE;
+			}
+
 			PHP_SHA256Init(&context);
 			read_len = end_of_phar;
 
@@ -1683,6 +1697,13 @@
 			unsigned char digest[20];
 			PHP_SHA1_CTX  context;
 
+			if (sig_len < sizeof(digest)) {
+				if (error) {
+					spprintf(error, 0, "broken signature");
+				}
+				return FAILURE;
+			}
+
 			PHP_SHA1Init(&context);
 			read_len = end_of_phar;
 
@@ -1715,6 +1736,13 @@
 		case PHAR_SIG_MD5: {
 			unsigned char digest[16];
 			PHP_MD5_CTX   context;
+
+			if (sig_len < sizeof(digest)) {
+				if (error) {
+					spprintf(error, 0, "broken signature");
+				}
+				return FAILURE;
+			}
 
 			PHP_MD5Init(&context);
 			read_len = end_of_phar;
```
