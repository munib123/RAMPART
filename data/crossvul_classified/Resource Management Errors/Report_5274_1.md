# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5274_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5274_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 531-571 of the vulnerable file.

			return (ARCHIVE_FATAL);
		}
		a->format = &(a->formats[slot]);
	}

	a->archive.state = ARCHIVE_STATE_HEADER;

	/* Ensure libarchive starts from the first node in a multivolume set */
	client_switch_proxy(a->filter, 0);
	return (e);
}

/*
 * Allow each registered stream transform to bid on whether
 * it wants to handle this stream.  Repeat until we've finished
 * building the pipeline.
 */
static int
choose_filters(struct archive_read *a)
{
	int number_bidders, i, bid, best_bid;
	struct archive_read_filter_bidder *bidder, *best_bidder;
	struct archive_read_filter *filter;
	ssize_t avail;
	int r;

	for (;;) {
		number_bidders = sizeof(a->bidders) / sizeof(a->bidders[0]);

		best_bid = 0;
		best_bidder = NULL;

		bidder = a->bidders;
		for (i = 0; i < number_bidders; i++, bidder++) {
			if (bidder->bid != NULL) {
				bid = (bidder->bid)(bidder, a->filter);
				if (bid > best_bid) {
					best_bid = bid;
					best_bidder = bidder;
				}
			}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -548,13 +548,13 @@
 static int
 choose_filters(struct archive_read *a)
 {
-	int number_bidders, i, bid, best_bid;
+	int number_bidders, i, bid, best_bid, n;
 	struct archive_read_filter_bidder *bidder, *best_bidder;
 	struct archive_read_filter *filter;
 	ssize_t avail;
 	int r;
 
-	for (;;) {
+	for (n = 0; n < 25; ++n) {
 		number_bidders = sizeof(a->bidders) / sizeof(a->bidders[0]);
 
 		best_bid = 0;
@@ -600,6 +600,9 @@
 			return (ARCHIVE_FATAL);
 		}
 	}
+	archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
+	    "Input requires too many filters for decoding");
+	return (ARCHIVE_FATAL);
 }
 
 /*
```
