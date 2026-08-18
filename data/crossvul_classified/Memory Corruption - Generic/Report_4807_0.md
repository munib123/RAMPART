# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4807_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4807_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 410-450 of the vulnerable file.

		/*
		 * If we fail to parse the length, it might be because the
		 * server is trying to send us the packfile already.
		 */
		if (bufflen >= 4 && !git__prefixcmp(line, "PACK")) {
			giterr_clear();
			*out = line;
			return pack_pkt(head);
		}

		return (int)len;
	}

	/*
	 * If we were given a buffer length, then make sure there is
	 * enough in the buffer to satisfy this line
	 */
	if (bufflen > 0 && bufflen < (size_t)len)
		return GIT_EBUFS;

	line += PKT_LEN_SIZE;
	/*
	 * TODO: How do we deal with empty lines? Try again? with the next
	 * line?
	 */
	if (len == PKT_LEN_SIZE) {
		*head = NULL;
		*out = line;
		return 0;
	}

	if (len == 0) { /* Flush pkt */
		*out = line;
		return flush_pkt(head);
	}

	len -= PKT_LEN_SIZE; /* the encoded length includes its own size */

	if (*line == GIT_SIDE_BAND_DATA)
		ret = data_pkt(head, line, len);
	else if (*line == GIT_SIDE_BAND_PROGRESS)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -426,6 +426,14 @@
 	 */
 	if (bufflen > 0 && bufflen < (size_t)len)
 		return GIT_EBUFS;
+
+	/*
+	 * The length has to be exactly 0 in case of a flush
+	 * packet or greater than PKT_LEN_SIZE, as the decoded
+	 * length includes its own encoded length of four bytes.
+	 */
+	if (len != 0 && len < PKT_LEN_SIZE)
+		return GIT_ERROR;
 
 	line += PKT_LEN_SIZE;
 	/*
```
