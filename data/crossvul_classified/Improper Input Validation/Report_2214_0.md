# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2214_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2214_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 55-95 of the vulnerable file.

	BYTE * const oend = op + osize;
	BYTE *cpy;
	unsigned token;
	size_t length;
	size_t dec32table[] = {0, 3, 2, 3, 0, 0, 0, 0};
#if LZ4_ARCH64
	size_t dec64table[] = {0, 0, 0, -1, 0, 1, 2, 3};
#endif

	while (1) {

		/* get runlength */
		token = *ip++;
		length = (token >> ML_BITS);
		if (length == RUN_MASK) {
			size_t len;

			len = *ip++;
			for (; len == 255; length += 255)
				len = *ip++;
			length += len;
		}

		/* copy literals */
		cpy = op + length;
		if (unlikely(cpy > oend - COPYLENGTH)) {
			/*
			 * Error: not enough place for another match
			 * (min 4) + 5 literals
			 */
			if (cpy != oend)
				goto _output_error;

			memcpy(op, ip, length);
			ip += length;
			break; /* EOF */
		}
		LZ4_WILDCOPY(ip, op, cpy);
		ip -= (op - cpy);
		op = cpy;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,6 +72,8 @@
 			len = *ip++;
 			for (; len == 255; length += 255)
 				len = *ip++;
+			if (unlikely(length > (size_t)(length + len)))
+				goto _output_error;
 			length += len;
 		}
 
```
