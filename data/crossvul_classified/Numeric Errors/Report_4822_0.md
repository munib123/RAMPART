# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 4822_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4822_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1286-1326 of the vulnerable file.

	switch(format) {
		case TAG_FMT_SBYTE:     return *(signed char *)value;
		case TAG_FMT_BYTE:      return *(uchar *)value;

		case TAG_FMT_USHORT:    return php_ifd_get16u(value, motorola_intel);
		case TAG_FMT_ULONG:     return php_ifd_get32u(value, motorola_intel);

		case TAG_FMT_URATIONAL:
			u_den = php_ifd_get32u(4+(char *)value, motorola_intel);
			if (u_den == 0) {
				return 0;
			} else {
				return php_ifd_get32u(value, motorola_intel) / u_den;
			}

		case TAG_FMT_SRATIONAL:
			s_den = php_ifd_get32s(4+(char *)value, motorola_intel);
			if (s_den == 0) {
				return 0;
			} else {
				return php_ifd_get32s(value, motorola_intel) / s_den;
			}

		case TAG_FMT_SSHORT:    return php_ifd_get16u(value, motorola_intel);
		case TAG_FMT_SLONG:     return php_ifd_get32s(value, motorola_intel);

		/* Not sure if this is correct (never seen float used in Exif format) */
		case TAG_FMT_SINGLE:
#ifdef EXIF_DEBUG
			php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Found value of type single");
#endif
			return (size_t)*(float *)value;
		case TAG_FMT_DOUBLE:
#ifdef EXIF_DEBUG
			php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Found value of type double");
#endif
			return (size_t)*(double *)value;
	}
	return 0;
}
/* }}} */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1303,7 +1303,7 @@
 			if (s_den == 0) {
 				return 0;
 			} else {
-				return php_ifd_get32s(value, motorola_intel) / s_den;
+				return (size_t)((double)php_ifd_get32s(value, motorola_intel) / s_den);
 			}
 
 		case TAG_FMT_SSHORT:    return php_ifd_get16u(value, motorola_intel);
```
