# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 798_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `798_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1973-2000 of the vulnerable file.

GF_Err gf_bin128_parse(const char *string, bin128 value)
{
	u32 len;
	u32	i=0;
	if (!strnicmp(string, "0x", 2)) string += 2;
	len = (u32) strlen(string);
	if (len >= 32) {
		u32 j;
		for (j=0; j<len; j+=2) {
			u32 v;
			char szV[5];

			while (string[j] && !isalnum(string[j]))
				j++;
			if (!string[j])
				break;
			sprintf(szV, "%c%c", string[j], string[j+1]);
			sscanf(szV, "%x", &v);
			value[i] = v;
			i++;
		}
	}
	if (i != 16) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_CORE, ("[CORE] 128bit blob is not 16-bytes long: %s\n", string));
		return GF_BAD_PARAM;
	}
	return GF_OK;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1990,6 +1990,11 @@
 			sscanf(szV, "%x", &v);
 			value[i] = v;
 			i++;
+			if (i > 15) {
+				// force error check below
+				i++;
+				break;
+			}
 		}
 	}
 	if (i != 16) {
```
