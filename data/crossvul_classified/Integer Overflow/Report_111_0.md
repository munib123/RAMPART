# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 111_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `111_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 522-565 of the vulnerable file.

		return -1;

	return 0;
}

int git_delta_apply(
	void **out,
	size_t *out_len,
	const unsigned char *base,
	size_t base_len,
	const unsigned char *delta,
	size_t delta_len)
{
	const unsigned char *delta_end = delta + delta_len;
	size_t base_sz, res_sz, alloc_sz;
	unsigned char *res_dp;

	*out = NULL;
	*out_len = 0;

	/* Check that the base size matches the data we were given;
	* if not we would underflow while accessing data from the
	* base object, resulting in data corruption or segfault.
	*/
	if ((hdr_sz(&base_sz, &delta, delta_end) < 0) || (base_sz != base_len)) {
		giterr_set(GITERR_INVALID, "failed to apply delta: base size does not match given data");
		return -1;
	}

	if (hdr_sz(&res_sz, &delta, delta_end) < 0) {
		giterr_set(GITERR_INVALID, "failed to apply delta: base size does not match given data");
		return -1;
	}

	GITERR_CHECK_ALLOC_ADD(&alloc_sz, res_sz, 1);
	res_dp = git__malloc(alloc_sz);
	GITERR_CHECK_ALLOC(res_dp);

	res_dp[res_sz] = '\0';
	*out = res_dp;
	*out_len = res_sz;

	while (delta < delta_end) {
		unsigned char cmd = *delta++;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -539,10 +539,11 @@
 	*out = NULL;
 	*out_len = 0;
 
-	/* Check that the base size matches the data we were given;
-	* if not we would underflow while accessing data from the
-	* base object, resulting in data corruption or segfault.
-	*/
+	/*
+	 * Check that the base size matches the data we were given;
+	 * if not we would underflow while accessing data from the
+	 * base object, resulting in data corruption or segfault.
+	 */
 	if ((hdr_sz(&base_sz, &delta, delta_end) < 0) || (base_sz != base_len)) {
 		giterr_set(GITERR_INVALID, "failed to apply delta: base size does not match given data");
 		return -1;
@@ -564,19 +565,18 @@
 	while (delta < delta_end) {
 		unsigned char cmd = *delta++;
 		if (cmd & 0x80) {
-			/* cmd is a copy instruction; copy from the base.
-			*/
+			/* cmd is a copy instruction; copy from the base. */
 			size_t off = 0, len = 0;
 
 			if (cmd & 0x01) off = *delta++;
 			if (cmd & 0x02) off |= *delta++ << 8UL;
 			if (cmd & 0x04) off |= *delta++ << 16UL;
-			if (cmd & 0x08) off |= *delta++ << 24UL;
+			if (cmd & 0x08) off |= ((unsigned) *delta++ << 24UL);
 
 			if (cmd & 0x10) len = *delta++;
 			if (cmd & 0x20) len |= *delta++ << 8UL;
 			if (cmd & 0x40) len |= *delta++ << 16UL;
-			if (!len)		len = 0x10000;
+			if (!len)       len = 0x10000;
 
 			if (base_len < off + len || res_sz < len)
 				goto fail;
@@ -584,11 +584,11 @@
 			res_dp += len;
 			res_sz -= len;
 
-		}
-		else if (cmd) {
-			/* cmd is a literal insert instruction; copy from
-			* the delta stream itself.
-			*/
+		} else if (cmd) {
+			/*
+			 * cmd is a literal insert instruction; copy from
+			 * the delta stream itself.
+			 */
 			if (delta_end - delta < cmd || res_sz < cmd)
 				goto fail;
 			memcpy(res_dp, delta, cmd);
@@ -596,10 +596,8 @@
 			res_dp += cmd;
 			res_sz -= cmd;
 
-		}
-		else {
-			/* cmd == 0 is reserved for future encodings.
-			*/
+		} else {
+			/* cmd == 0 is reserved for future encodings. */
 			goto fail;
 		}
 	}
```
