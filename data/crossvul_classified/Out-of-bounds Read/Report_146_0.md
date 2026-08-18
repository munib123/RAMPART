# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 146_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `146_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 59-99 of the vulnerable file.

				string->length, string->size,
				section_name, type_string, string->string);
		break;
	}
}

static int string_scan_range(RList *list, RBinFile *bf, int min,
			      const ut64 from, const ut64 to, int type) {
	ut8 tmp[R_STRING_SCAN_BUFFER_SIZE];
	ut64 str_start, needle = from;
	int count = 0, i, rc, runes;
	int str_type = R_STRING_TYPE_DETECT;

	if (type == -1) {
		type = R_STRING_TYPE_DETECT;
	}
	if (from >= to) {
		eprintf ("Invalid range to find strings 0x%llx .. 0x%llx\n", from, to);
		return -1;
	}
	ut8 *buf = calloc (to - from, 1);
	if (!buf || !min) {
		return -1;
	}
	r_buf_read_at (bf->buf, from, buf, to - from);
	// may oobread
	while (needle < to) {
		rc = r_utf8_decode (buf + needle - from, to - needle, NULL);
		if (!rc) {
			needle++;
			continue;
		}
		if (type == R_STRING_TYPE_DETECT) {
			char *w = (char *)buf + needle + rc - from;
			if ((to - needle) > 5) {
				bool is_wide32 = needle + rc + 2 < to && !w[0] && !w[1] && !w[2] && w[3] && !w[4];
				if (is_wide32) {
					str_type = R_STRING_TYPE_WIDE32;
				} else {
					bool is_wide = needle + rc + 2 < to && !w[0] && w[1] && !w[2];
					str_type = is_wide? R_STRING_TYPE_WIDE: R_STRING_TYPE_ASCII;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -76,11 +76,12 @@
 		eprintf ("Invalid range to find strings 0x%llx .. 0x%llx\n", from, to);
 		return -1;
 	}
-	ut8 *buf = calloc (to - from, 1);
+	int len = to - from;
+	ut8 *buf = calloc (len, 1);
 	if (!buf || !min) {
 		return -1;
 	}
-	r_buf_read_at (bf->buf, from, buf, to - from);
+	r_buf_read_at (bf->buf, from, buf, len);
 	// may oobread
 	while (needle < to) {
 		rc = r_utf8_decode (buf + needle - from, to - needle, NULL);
@@ -90,8 +91,8 @@
 		}
 		if (type == R_STRING_TYPE_DETECT) {
 			char *w = (char *)buf + needle + rc - from;
-			if ((to - needle) > 5) {
-				bool is_wide32 = needle + rc + 2 < to && !w[0] && !w[1] && !w[2] && w[3] && !w[4];
+			if ((to - needle) > 5 + rc) {
+				bool is_wide32 = (needle + rc + 2 < to) && (!w[0] && !w[1] && !w[2] && w[3] && !w[4]);
 				if (is_wide32) {
 					str_type = R_STRING_TYPE_WIDE32;
 				} else {
```
