# CrossVul Fix Pair: Double Free in c
**Pair ID:** 62_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `62_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 367-407 of the vulnerable file.

		goto start_over;
	}
	return (ARCHIVE_OK);
}

static int
_warc_read(struct archive_read *a, const void **buf, size_t *bsz, int64_t *off)
{
	struct warc_s *w = a->format->data;
	const char *rab;
	ssize_t nrd;

	if (w->cntoff >= w->cntlen) {
	eof:
		/* it's our lucky day, no work, we can leave early */
		*buf = NULL;
		*bsz = 0U;
		*off = w->cntoff + 4U/*for \r\n\r\n separator*/;
		w->unconsumed = 0U;
		return (ARCHIVE_EOF);
	}

	rab = __archive_read_ahead(a, 1U, &nrd);
	if (nrd < 0) {
		*bsz = 0U;
		/* big catastrophe */
		return (int)nrd;
	} else if (nrd == 0) {
		goto eof;
	} else if ((size_t)nrd > w->cntlen - w->cntoff) {
		/* clamp to content-length */
		nrd = w->cntlen - w->cntoff;
	}
	*off = w->cntoff;
	*bsz = nrd;
	*buf = rab;

	w->cntoff += nrd;
	w->unconsumed = (size_t)nrd;
	return (ARCHIVE_OK);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -384,6 +384,11 @@
 		*off = w->cntoff + 4U/*for \r\n\r\n separator*/;
 		w->unconsumed = 0U;
 		return (ARCHIVE_EOF);
+	}
+
+	if (w->unconsumed) {
+		__archive_read_consume(a, w->unconsumed);
+		w->unconsumed = 0U;
 	}
 
 	rab = __archive_read_ahead(a, 1U, &nrd);
```
