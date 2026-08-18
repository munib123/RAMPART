# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2900_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2900_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 335-376 of the vulnerable file.

					char ch = tmp[j];
					if (ch != '\n' && ch != '\r' && ch != '\t') {
						if (!IS_PRINTABLE (tmp[j])) {
							continue;
						}
					}
				}
			}
			if (list) {
				RBinString *new = R_NEW0 (RBinString);
				if (!new) {
					break;
				}
				new->type = str_type;
				new->length = runes;
				new->size = needle - str_start;
				new->ordinal = count++;
				// TODO: move into adjust_offset
				switch (str_type) {
				case R_STRING_TYPE_WIDE:
					{
						const ut8 *p = buf  + str_start - 2;
						if (p[0] == 0xff && p[1] == 0xfe) {
							str_start -= 2; // \xff\xfe
						}
					}
					break;
				case R_STRING_TYPE_WIDE32:
					{
						const ut8 *p = buf  + str_start - 4;
						if (p[0] == 0xff && p[1] == 0xfe) {
							str_start -= 4; // \xff\xfe\x00\x00
						}
					}
					break;
				}
				new->paddr = new->vaddr = str_start;
				new->string = r_str_ndup ((const char *)tmp, i);
				r_list_append (list, new);
			} else {
				// DUMP TO STDOUT. raw dumping for rabin2 -zzz
				printf ("0x%08" PFMT64x " %s\n", str_start, tmp);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -352,16 +352,16 @@
 				// TODO: move into adjust_offset
 				switch (str_type) {
 				case R_STRING_TYPE_WIDE:
-					{
-						const ut8 *p = buf  + str_start - 2;
+					if (str_start > 1) {
+						const ut8 *p = buf + str_start - 2;
 						if (p[0] == 0xff && p[1] == 0xfe) {
 							str_start -= 2; // \xff\xfe
 						}
 					}
 					break;
 				case R_STRING_TYPE_WIDE32:
-					{
-						const ut8 *p = buf  + str_start - 4;
+					if (str_start > 3) {
+						const ut8 *p = buf + str_start - 4;
 						if (p[0] == 0xff && p[1] == 0xfe) {
 							str_start -= 4; // \xff\xfe\x00\x00
 						}
```
