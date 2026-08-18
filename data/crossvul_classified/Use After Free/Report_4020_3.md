# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4020_3
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4020_3`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 263-303 of the vulnerable file.


	/* Read the number of tags */
	c = exif_get_short (buf + datao, n->order);
	datao += 2;

	/* Remove any old entries */
	exif_mnote_data_pentax_clear (n);

	/* Reserve enough space for all the possible MakerNote tags */
	n->entries = exif_mem_alloc (en->mem, sizeof (MnotePentaxEntry) * c);
	if (!n->entries) {
		EXIF_LOG_NO_MEMORY(en->log, "ExifMnoteDataPentax", sizeof (MnotePentaxEntry) * c);
		return;
	}

	/* Parse all c entries, storing ones that are successfully parsed */
	tcount = 0;
	for (i = c, o = datao; i; --i, o += 12) {
		size_t s;

		if (CHECKOVERFLOW(o,buf_size,12)) {
			exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
				  "ExifMnoteDataPentax", "Short MakerNote");
			break;
		}

		n->entries[tcount].tag        = exif_get_short (buf + o + 0, n->order) + base;
		n->entries[tcount].format     = exif_get_short (buf + o + 2, n->order);
		n->entries[tcount].components = exif_get_long  (buf + o + 4, n->order);
		n->entries[tcount].order      = n->order;

		exif_log (en->log, EXIF_LOG_CODE_DEBUG, "ExifMnotePentax",
			  "Loading entry 0x%x ('%s')...", n->entries[tcount].tag,
			  mnote_pentax_tag_get_name (n->entries[tcount].tag));

		/* Check if we overflow the multiplication. Use buf_size as the max size for integer overflow detection,
		 * we will check the buffer sizes closer later. */
		if (	exif_format_get_size (n->entries[tcount].format) &&
			buf_size / exif_format_get_size (n->entries[tcount].format) < n->entries[tcount].components
		) {
			exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -280,6 +280,7 @@
 	for (i = c, o = datao; i; --i, o += 12) {
 		size_t s;
 
+		memset(&n->entries[tcount], 0, sizeof(MnotePentaxEntry));
 		if (CHECKOVERFLOW(o,buf_size,12)) {
 			exif_log (en->log, EXIF_LOG_CODE_CORRUPT_DATA,
 				  "ExifMnoteDataPentax", "Short MakerNote");
```
