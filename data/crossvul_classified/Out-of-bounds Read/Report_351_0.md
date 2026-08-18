# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 86-126 of the vulnerable file.

		/* high tag number */
		size_t n = SC_ASN1_TAGNUM_SIZE - 1;
		/* search the last tag octet */
		while (left-- != 0 && n != 0) {
			tag <<= 8;
			tag |= *p;
			if ((*p++ & 0x80) == 0)
				break;
			n--;
		}
		if (left == 0 || n == 0)
			/* either an invalid tag or it doesn't fit in
			 * unsigned int */
			return SC_ERROR_INVALID_ASN1_OBJECT;
	}

	/* parse length byte(s) */
	len = *p & 0x7f;
	if (*p++ & 0x80) {
		unsigned int a = 0;
		if (len > 4 || len > left)
			return SC_ERROR_INVALID_ASN1_OBJECT;
		left -= len;
		for (i = 0; i < len; i++) {
			a <<= 8;
			a |= *p;
			p++;
		}
		len = a;
	}

	*cla_out = cla;
	*tag_out = tag;
	*taglen = len;
	*buf = p;

	if (len > left)
		return SC_ERROR_ASN1_END_OF_CONTENTS;

	return SC_SUCCESS;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,6 +103,7 @@
 	len = *p & 0x7f;
 	if (*p++ & 0x80) {
 		unsigned int a = 0;
+		left--;
 		if (len > 4 || len > left)
 			return SC_ERROR_INVALID_ASN1_OBJECT;
 		left -= len;
```
