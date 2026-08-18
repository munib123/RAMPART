# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4809_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4809_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 420-461 of the vulnerable file.

		return (int)len;
	}

	/*
	 * If we were given a buffer length, then make sure there is
	 * enough in the buffer to satisfy this line
	 */
	if (bufflen > 0 && bufflen < (size_t)len)
		return GIT_EBUFS;

	/*
	 * The length has to be exactly 0 in case of a flush
	 * packet or greater than PKT_LEN_SIZE, as the decoded
	 * length includes its own encoded length of four bytes.
	 */
	if (len != 0 && len < PKT_LEN_SIZE)
		return GIT_ERROR;

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
		ret = sideband_progress_pkt(head, line, len);
	else if (*line == GIT_SIDE_BAND_ERROR)
		ret = sideband_error_pkt(head, line, len);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -437,13 +437,13 @@
 
 	line += PKT_LEN_SIZE;
 	/*
-	 * TODO: How do we deal with empty lines? Try again? with the next
-	 * line?
+	 * The Git protocol does not specify empty lines as part
+	 * of the protocol. Not knowing what to do with an empty
+	 * line, we should return an error upon hitting one.
 	 */
 	if (len == PKT_LEN_SIZE) {
-		*head = NULL;
-		*out = line;
-		return 0;
+		giterr_set_str(GITERR_NET, "Invalid empty packet");
+		return GIT_ERROR;
 	}
 
 	if (len == 0) { /* Flush pkt */
```
