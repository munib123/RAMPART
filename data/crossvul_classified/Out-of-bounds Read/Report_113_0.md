# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 113_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `113_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 551-594 of the vulnerable file.


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
		if (cmd & 0x80) {
			/* cmd is a copy instruction; copy from the base. */
			size_t off = 0, len = 0;

			if (cmd & 0x01) off = *delta++;
			if (cmd & 0x02) off |= *delta++ << 8UL;
			if (cmd & 0x04) off |= *delta++ << 16UL;
			if (cmd & 0x08) off |= ((unsigned) *delta++ << 24UL);

			if (cmd & 0x10) len = *delta++;
			if (cmd & 0x20) len |= *delta++ << 8UL;
			if (cmd & 0x40) len |= *delta++ << 16UL;
			if (!len)       len = 0x10000;

			if (base_len < off + len || res_sz < len)
				goto fail;
			memcpy(res_dp, base + off, len);
			res_dp += len;
			res_sz -= len;

		} else if (cmd) {
			/*
			 * cmd is a literal insert instruction; copy from
			 * the delta stream itself.
			 */
			if (delta_end - delta < cmd || res_sz < cmd)
				goto fail;
			memcpy(res_dp, delta, cmd);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -568,15 +568,17 @@
 			/* cmd is a copy instruction; copy from the base. */
 			size_t off = 0, len = 0;
 
-			if (cmd & 0x01) off = *delta++;
-			if (cmd & 0x02) off |= *delta++ << 8UL;
-			if (cmd & 0x04) off |= *delta++ << 16UL;
-			if (cmd & 0x08) off |= ((unsigned) *delta++ << 24UL);
-
-			if (cmd & 0x10) len = *delta++;
-			if (cmd & 0x20) len |= *delta++ << 8UL;
-			if (cmd & 0x40) len |= *delta++ << 16UL;
+#define ADD_DELTA(o, shift) { if (delta < delta_end) (o) |= ((unsigned) *delta++ << shift); else goto fail; }
+			if (cmd & 0x01) ADD_DELTA(off, 0UL);
+			if (cmd & 0x02) ADD_DELTA(off, 8UL);
+			if (cmd & 0x04) ADD_DELTA(off, 16UL);
+			if (cmd & 0x08) ADD_DELTA(off, 24UL);
+
+			if (cmd & 0x10) ADD_DELTA(len, 0UL);
+			if (cmd & 0x20) ADD_DELTA(len, 8UL);
+			if (cmd & 0x40) ADD_DELTA(len, 16UL);
 			if (!len)       len = 0x10000;
+#undef ADD_DELTA
 
 			if (base_len < off + len || res_sz < len)
 				goto fail;
```
