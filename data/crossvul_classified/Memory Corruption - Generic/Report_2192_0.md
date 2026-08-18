# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2192_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2192_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 500-540 of the vulnerable file.

			add_assoc_stringl(*subarray, "cpu", (char*)cp, n, 1);
			cp += n;
			n = *cp & 0xFF;
			cp++;
			add_assoc_stringl(*subarray, "os", (char*)cp, n, 1);
			cp += n;
			break;
		case DNS_T_TXT:
			{
				int ll = 0;
				zval *entries = NULL;

				add_assoc_string(*subarray, "type", "TXT", 1);
				tp = emalloc(dlen + 1);
				
				MAKE_STD_ZVAL(entries);
				array_init(entries);
				
				while (ll < dlen) {
					n = cp[ll];
					memcpy(tp + ll , cp + ll + 1, n);
					add_next_index_stringl(entries, cp + ll + 1, n, 1);
					ll = ll + n + 1;
				}
				tp[dlen] = '\0';
				cp += dlen;

				add_assoc_stringl(*subarray, "txt", tp, (dlen>0)?dlen - 1:0, 0);
				add_assoc_zval(*subarray, "entries", entries);
			}
			break;
		case DNS_T_SOA:
			add_assoc_string(*subarray, "type", "SOA", 1);
			n = dn_expand(answer->qb2, answer->qb2+65536, cp, name, (sizeof name) -2);
			if (n < 0) {
				return NULL;
			}
			cp += n;
			add_assoc_string(*subarray, "mname", name, 1);
			n = dn_expand(answer->qb2, answer->qb2+65536, cp, name, (sizeof name) -2);
			if (n < 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -517,6 +517,10 @@
 				
 				while (ll < dlen) {
 					n = cp[ll];
+					if ((ll + n) >= dlen) {
+						// Invalid chunk length, truncate
+						n = dlen - (ll + 1);
+					}
 					memcpy(tp + ll , cp + ll + 1, n);
 					add_next_index_stringl(entries, cp + ll + 1, n, 1);
 					ll = ll + n + 1;
```
