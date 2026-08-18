# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 514_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `514_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 675-715 of the vulnerable file.

						}
						return NULL;
					}

					state->uri->hostText.afterLast = first; /* HOST END */

					/* Copy missing quads right before IPv4 */
					memcpy(state->uri->hostData.ip6->data + 16 - 4 - 2 * quadsAfterZipperCount,
								quadsAfterZipper, 2 * quadsAfterZipperCount);

					/* Copy last IPv4 octet */
					state->uri->hostData.ip6->data[16 - 4 + 3] = uriGetOctetValue(digitHistory, digitCount);

					return first + 1;

				default:
					URI_FUNC(StopSyntax)(state, first, memory);
					return NULL;
				}
				first++;
			}
		} else {
			/* Eat while no dot in sight */
			int letterAmong = 0;
			int walking = 1;
			do {
				switch (*first) {
				case URI_SET_HEX_LETTER_LOWER:
					letterAmong = 1;
					if (digitCount == 4) {
						URI_FUNC(StopSyntax)(state, first, memory);
						return NULL;
					}
					digitHistory[digitCount] = (unsigned char)(15 + *first - _UT('f'));
					digitCount++;
					break;

				case URI_SET_HEX_LETTER_UPPER:
					letterAmong = 1;
					if (digitCount == 4) {
						URI_FUNC(StopSyntax)(state, first, memory);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -692,6 +692,11 @@
 					return NULL;
 				}
 				first++;
+
+				if (first >= afterLast) {
+					URI_FUNC(StopSyntax)(state, first, memory);
+					return NULL;
+				}
 			}
 		} else {
 			/* Eat while no dot in sight */
```
