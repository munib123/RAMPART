# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2660_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2660_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1172-1213 of the vulnerable file.

			if (!pbody->cf_present) {
				pbody->cf = cf;
				pbody->cf_present = 1;
			}
			break;
		case E_TIM:
			memcpy(&tim, p + offset, 2);
			offset += 2;
			length -= 2;
			if (tim.length <= 3) {
				offset += tim.length;
				length -= tim.length;
				break;
			}
			if (tim.length - 3 > (int)sizeof tim.bitmap)
				return 0;
			memcpy(&tim.count, p + offset, 3);
			offset += 3;
			length -= 3;

			memcpy(tim.bitmap, p + (tim.length - 3),
			    (tim.length - 3));
			offset += tim.length - 3;
			length -= tim.length - 3;
			/*
			 * Present and not truncated.
			 *
			 * If we haven't already seen a TIM IE,
			 * copy this one, otherwise ignore this one,
			 * so we later report the first one we saw.
			 */
			if (!pbody->tim_present) {
				pbody->tim = tim;
				pbody->tim_present = 1;
			}
			break;
		default:
#if 0
			ND_PRINT((ndo, "(1) unhandled element_id (%d)  ",
			    *(p + offset)));
#endif
			offset += 2 + elementlen;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1189,8 +1189,7 @@
 			offset += 3;
 			length -= 3;
 
-			memcpy(tim.bitmap, p + (tim.length - 3),
-			    (tim.length - 3));
+			memcpy(tim.bitmap, p + offset + 3, tim.length - 3);
 			offset += tim.length - 3;
 			length -= tim.length - 3;
 			/*
```
