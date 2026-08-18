# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 5540_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5540_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 656-696 of the vulnerable file.

	struct archive_write *a = (struct archive_write *)_a;
	int ret = ARCHIVE_OK;

	archive_check_magic(&a->archive, ARCHIVE_WRITE_MAGIC,
	    ARCHIVE_STATE_HEADER | ARCHIVE_STATE_DATA,
	    "archive_write_finish_entry");
	if (a->archive.state & ARCHIVE_STATE_DATA
	    && a->format_finish_entry != NULL)
		ret = (a->format_finish_entry)(a);
	a->archive.state = ARCHIVE_STATE_HEADER;
	return (ret);
}

/*
 * Note that the compressor is responsible for blocking.
 */
static ssize_t
_archive_write_data(struct archive *_a, const void *buff, size_t s)
{
	struct archive_write *a = (struct archive_write *)_a;
	archive_check_magic(&a->archive, ARCHIVE_WRITE_MAGIC,
	    ARCHIVE_STATE_DATA, "archive_write_data");
	archive_clear_error(&a->archive);
	return ((a->format_write_data)(a, buff, s));
}

static struct archive_write_filter *
filter_lookup(struct archive *_a, int n)
{
	struct archive_write *a = (struct archive_write *)_a;
	struct archive_write_filter *f = a->filter_first;
	if (n == -1)
		return a->filter_last;
	if (n < 0)
		return NULL;
	while (n > 0 && f != NULL) {
		f = f->next_filter;
		--n;
	}
	return f;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -673,8 +673,13 @@
 _archive_write_data(struct archive *_a, const void *buff, size_t s)
 {
 	struct archive_write *a = (struct archive_write *)_a;
+	const size_t max_write = INT_MAX;
+
 	archive_check_magic(&a->archive, ARCHIVE_WRITE_MAGIC,
 	    ARCHIVE_STATE_DATA, "archive_write_data");
+	/* In particular, this catches attempts to pass negative values. */
+	if (s > max_write)
+		s = max_write;
 	archive_clear_error(&a->archive);
 	return ((a->format_write_data)(a, buff, s));
 }
```
