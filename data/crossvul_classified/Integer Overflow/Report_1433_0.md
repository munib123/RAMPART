# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 1433_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1433_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 175-215 of the vulnerable file.

		  "Loading entry 0x%x ('%s')...", entry->tag,
		  exif_tag_get_name (entry->tag));

	/* {0,1,2,4,8} x { 0x00000000 .. 0xffffffff } 
	 *   -> { 0x000000000 .. 0x7fffffff8 } */
	s = exif_format_get_size(entry->format) * entry->components;
	if ((s < entry->components) || (s == 0)){
		return 0;
	}

	/*
	 * Size? If bigger than 4 bytes, the actual data is not
	 * in the entry but somewhere else (offset).
	 */
	if (s > 4)
		doff = exif_get_long (d + offset + 8, data->priv->order);
	else
		doff = offset + 8;

	/* Sanity checks */
	if ((doff + s < doff) || (doff + s < s) || (doff + s > size)) {
		exif_log (data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData",
				  "Tag data past end of buffer (%u > %u)", doff+s, size);	
		return 0;
	}

	entry->data = exif_data_alloc (data, s);
	if (entry->data) {
		entry->size = s;
		memcpy (entry->data, d + doff, s);
	} else {
		EXIF_LOG_NO_MEMORY(data->priv->log, "ExifData", s);
		return 0;
	}

	/* If this is the MakerNote, remember the offset */
	if (entry->tag == EXIF_TAG_MAKER_NOTE) {
		if (!entry->data) {
			exif_log (data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData",
					  "MakerNote found with empty data");	
		} else if (entry->size > 6) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -192,9 +192,15 @@
 		doff = offset + 8;
 
 	/* Sanity checks */
-	if ((doff + s < doff) || (doff + s < s) || (doff + s > size)) {
+	if (doff >= size) {
 		exif_log (data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData",
-				  "Tag data past end of buffer (%u > %u)", doff+s, size);	
+				  "Tag starts past end of buffer (%u > %u)", doff, size);
+		return 0;
+	}
+
+	if (s > size - doff) {
+		exif_log (data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData",
+				  "Tag data goes past end of buffer (%u > %u)", doff+s, size);
 		return 0;
 	}
 
@@ -315,13 +321,14 @@
 			       unsigned int ds, ExifLong o, ExifLong s)
 {
 	/* Sanity checks */
-	if ((o + s < o) || (o + s < s) || (o + s > ds) || (o > ds)) {
-		exif_log (data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData",
-			  "Bogus thumbnail offset (%u) or size (%u).",
-			  o, s);
-		return;
-	}
-
+	if (o >= ds) {
+		exif_log (data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData", "Bogus thumbnail offset (%u).", o);
+		return;
+	}
+	if (s > ds - o) {
+		exif_log (data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData", "Bogus thumbnail size (%u), max would be %u.", s, ds-o);
+		return;
+	}
 	if (data->data) 
 		exif_mem_free (data->priv->mem, data->data);
 	if (!(data->data = exif_data_alloc (data, s))) {
@@ -947,7 +954,7 @@
 	exif_log (data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData", 
 		  "IFD 0 at %i.", (int) offset);
 
-	/* Sanity check the offset, being careful about overflow */
+	/* ds is restricted to 16 bit above, so offset is restricted too, and offset+8 should not overflow. */
 	if (offset > ds || offset + 6 + 2 > ds)
 		return;
 
@@ -956,6 +963,7 @@
 
 	/* IFD 1 offset */
 	n = exif_get_short (d + 6 + offset, data->priv->order);
+	/* offset < 2<<16, n is 16 bit at most, so this op will not overflow */
 	if (offset + 6 + 2 + 12 * n + 4 > ds)
 		return;
 
@@ -964,8 +972,8 @@
 		exif_log (data->priv->log, EXIF_LOG_CODE_DEBUG, "ExifData",
 			  "IFD 1 at %i.", (int) offset);
 
-		/* Sanity check. */
-		if (offset > ds || offset + 6 > ds) {
+		/* Sanity check. ds is ensured to be above 6 above, offset is 16bit */
+		if (offset > ds - 6) {
 			exif_log (data->priv->log, EXIF_LOG_CODE_CORRUPT_DATA,
 				  "ExifData", "Bogus offset of IFD1.");
 		} else {
```
