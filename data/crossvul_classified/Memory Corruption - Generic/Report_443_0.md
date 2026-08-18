# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 443_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `443_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 206-246 of the vulnerable file.

		const int valueRequiredChars = worstCase * valueLen;

		if (dest == NULL) {
			if (firstItem == URI_TRUE) {
				ampersandLen = 1;
				firstItem = URI_FALSE;
			}

			(*charsRequired) += ampersandLen + keyRequiredChars + ((value == NULL)
						? 0
						: 1 + valueRequiredChars);
		} else {
			URI_CHAR * afterKey;

			if ((write - dest) + ampersandLen + keyRequiredChars > maxChars) {
				return URI_ERROR_OUTPUT_TOO_LARGE;
			}

			/* Copy key */
			if (firstItem == URI_TRUE) {
				firstItem = URI_FALSE;
			} else {
				write[0] = _UT('&');
				write++;
			}
			afterKey = URI_FUNC(EscapeEx)(key, key + keyLen,
					write, spaceToPlus, normalizeBreaks);
			write += (afterKey - write);

			if (value != NULL) {
				URI_CHAR * afterValue;

				if ((write - dest) + 1 + valueRequiredChars > maxChars) {
					return URI_ERROR_OUTPUT_TOO_LARGE;
				}

				/* Copy value */
				write[0] = _UT('=');
				write++;
				afterValue = URI_FUNC(EscapeEx)(value, value + valueLen,
						write, spaceToPlus, normalizeBreaks);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -223,6 +223,7 @@
 
 			/* Copy key */
 			if (firstItem == URI_TRUE) {
+				ampersandLen = 1;
 				firstItem = URI_FALSE;
 			} else {
 				write[0] = _UT('&');
```
