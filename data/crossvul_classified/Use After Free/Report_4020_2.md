# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4020_2
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4020_2`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 408-448 of the vulnerable file.

	}

	/* Read the number of tags */
	c = exif_get_short (buf + o2, n->order);
	o2 += 2;

	/* Remove any old entries */
	exif_mnote_data_olympus_clear (n);

	/* Reserve enough space for all the possible MakerNote tags */
	n->entries = exif_mem_alloc (en->mem, sizeof (MnoteOlympusEntry) * c);
	if (!n->entries) {
		EXIF_LOG_NO_MEMORY(en->log, "ExifMnoteOlympus", sizeof (MnoteOlympusEntry) * c);
		return;
	}

	/* Parse all c entries, storing ones that are successfully parsed */
	tcount = 0;
	for (i = c, o = o2; i; --i, o += 12) {
		size_t s;
		if (CHECKOVERFLOW(o, buf_size, 12)) {
			exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
				  "ExifMnoteOlympus", "Short MakerNote");
			break;
		}

	    n->entries[tcount].tag        = exif_get_short (buf + o, n->order) + base;
	    n->entries[tcount].format     = exif_get_short (buf + o + 2, n->order);
	    n->entries[tcount].components = exif_get_long (buf + o + 4, n->order);
	    n->entries[tcount].order      = n->order;

	    exif_log (en->log, EXIF_LOG_CODE_DEBUG, "ExifMnoteOlympus",
		      "Loading entry 0x%x ('%s')...", n->entries[tcount].tag,
		      mnote_olympus_tag_get_name (n->entries[tcount].tag));
/*	    exif_log (en->log, EXIF_LOG_CODE_DEBUG, "ExifMnoteOlympus",
			    "0x%x %d %ld*(%d)",
		    n->entries[tcount].tag,
		    n->entries[tcount].format,
		    n->entries[tcount].components,
		    (int)exif_format_get_size(n->entries[tcount].format)); */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -425,6 +425,7 @@
 	tcount = 0;
 	for (i = c, o = o2; i; --i, o += 12) {
 		size_t s;
+		memset(&n->entries[tcount], 0, sizeof(MnoteOlympusEntry));
 		if (CHECKOVERFLOW(o, buf_size, 12)) {
 			exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
 				  "ExifMnoteOlympus", "Short MakerNote");
```
