# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 112_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `112_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 549-589 of the vulnerable file.

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
		if (cmd & 0x80) {
			/* cmd is a copy instruction; copy from the base. */
			size_t off = 0, len = 0;

#define ADD_DELTA(o, shift) { if (delta < delta_end) (o) |= ((unsigned) *delta++ << shift); else goto fail; }
			if (cmd & 0x01) ADD_DELTA(off, 0UL);
			if (cmd & 0x02) ADD_DELTA(off, 8UL);
			if (cmd & 0x04) ADD_DELTA(off, 16UL);
			if (cmd & 0x08) ADD_DELTA(off, 24UL);

			if (cmd & 0x10) ADD_DELTA(len, 0UL);
			if (cmd & 0x20) ADD_DELTA(len, 8UL);
			if (cmd & 0x40) ADD_DELTA(len, 16UL);
			if (!len)       len = 0x10000;
#undef ADD_DELTA

			if (base_len < off + len || res_sz < len)
				goto fail;
			memcpy(res_dp, base + off, len);
			res_dp += len;
			res_sz -= len;

		} else if (cmd) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -566,7 +566,7 @@
 		unsigned char cmd = *delta++;
 		if (cmd & 0x80) {
 			/* cmd is a copy instruction; copy from the base. */
-			size_t off = 0, len = 0;
+			size_t off = 0, len = 0, end;
 
 #define ADD_DELTA(o, shift) { if (delta < delta_end) (o) |= ((unsigned) *delta++ << shift); else goto fail; }
 			if (cmd & 0x01) ADD_DELTA(off, 0UL);
@@ -580,8 +580,10 @@
 			if (!len)       len = 0x10000;
 #undef ADD_DELTA
 
-			if (base_len < off + len || res_sz < len)
+			if (GIT_ADD_SIZET_OVERFLOW(&end, off, len) ||
+			    base_len < end || res_sz < len)
 				goto fail;
+
 			memcpy(res_dp, base + off, len);
 			res_dp += len;
 			res_sz -= len;
```
