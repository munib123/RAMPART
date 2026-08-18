# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1064_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1064_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1452-1492 of the vulnerable file.

				parm = *buf;
			}
			r = decode_bit_string(obj, objlen, (u8 *) parm, *len, invert);
			if (r >= 0) {
				*len = r;
				r = 0;
			}
		}
		break;
	case SC_ASN1_BIT_FIELD:
		if (parm != NULL)
			r = decode_bit_field(obj, objlen, (u8 *) parm, *len);
		break;
	case SC_ASN1_OCTET_STRING:
		if (parm != NULL) {
			size_t c;
			assert(len != NULL);

			/* Strip off padding zero */
			if ((entry->flags & SC_ASN1_UNSIGNED)
			 && obj[0] == 0x00 && objlen > 1) {
				objlen--;
				obj++;
			}

			/* Allocate buffer if needed */
			if (entry->flags & SC_ASN1_ALLOC) {
				u8 **buf = (u8 **) parm;
				*buf = malloc(objlen);
				if (*buf == NULL) {
					r = SC_ERROR_OUT_OF_MEMORY;
					break;
				}
				c = *len = objlen;
				parm = *buf;
			} else
				c = objlen > *len ? *len : objlen;

			memcpy(parm, obj, c);
			*len = c;
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1469,7 +1469,7 @@
 
 			/* Strip off padding zero */
 			if ((entry->flags & SC_ASN1_UNSIGNED)
-			 && obj[0] == 0x00 && objlen > 1) {
+					&& objlen > 1 && obj[0] == 0x00) {
 				objlen--;
 				obj++;
 			}
```
