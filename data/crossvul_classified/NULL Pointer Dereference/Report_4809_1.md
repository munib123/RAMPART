# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4809_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4809_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 742-789 of the vulnerable file.

	}

	while (line_len > 0) {
		error = git_pkt_parse_line(&pkt, line, &line_end, line_len);

		if (error == GIT_EBUFS) {
			/* Buffer the data when the inner packet is split
			 * across multiple sideband packets */
			if (!reading_from_buf)
				git_buf_put(data_pkt_buf, line, line_len);
			error = 0;
			goto done;
		}
		else if (error < 0)
			goto done;

		/* Advance in the buffer */
		line_len -= (line_end - line);
		line = line_end;

		/* When a valid packet with no content has been
		 * read, git_pkt_parse_line does not report an
		 * error, but the pkt pointer has not been set.
		 * Handle this by skipping over empty packets.
		 */
		if (pkt == NULL)
			continue;

		error = add_push_report_pkt(push, pkt);

		git_pkt_free(pkt);

		if (error < 0 && error != GIT_ITEROVER)
			goto done;
	}

	error = 0;

done:
	if (reading_from_buf)
		git_buf_consume(data_pkt_buf, line_end);
	return error;
}

static int parse_report(transport_smart *transport, git_push *push)
{
	git_pkt *pkt = NULL;
	const char *line_end = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -759,14 +759,6 @@
 		line_len -= (line_end - line);
 		line = line_end;
 
-		/* When a valid packet with no content has been
-		 * read, git_pkt_parse_line does not report an
-		 * error, but the pkt pointer has not been set.
-		 * Handle this by skipping over empty packets.
-		 */
-		if (pkt == NULL)
-			continue;
-
 		error = add_push_report_pkt(push, pkt);
 
 		git_pkt_free(pkt);
@@ -820,9 +812,6 @@
 		gitno_consume(buf, line_end);
 
 		error = 0;
-
-		if (pkt == NULL)
-			continue;
 
 		switch (pkt->type) {
 			case GIT_PKT_DATA:
```
