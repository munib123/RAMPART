# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 707_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `707_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 2085-2125 of the vulnerable file.

		fprintf(stderr, "\n");
	} else if (*(isodirrec + DR_ext_attr_length_offset) != 0) {
		fprintf(stderr, "\n ** Unexpected extended attribute length: ");
		dump_isodirrec(stderr, isodirrec);
		fprintf(stderr, "\n");
	}
#endif
	register_file(iso9660, file);
	return (file);
fail:
	archive_string_free(&file->name);
	free(file);
	return (NULL);
}

static int
parse_rockridge(struct archive_read *a, struct file_info *file,
    const unsigned char *p, const unsigned char *end)
{
	struct iso9660 *iso9660;

	iso9660 = (struct iso9660 *)(a->format->data);

	while (p + 4 <= end  /* Enough space for another entry. */
	    && p[0] >= 'A' && p[0] <= 'Z' /* Sanity-check 1st char of name. */
	    && p[1] >= 'A' && p[1] <= 'Z' /* Sanity-check 2nd char of name. */
	    && p[2] >= 4 /* Sanity-check length. */
	    && p + p[2] <= end) { /* Sanity-check length. */
		const unsigned char *data = p + 4;
		int data_length = p[2] - 4;
		int version = p[3];

		switch(p[0]) {
		case 'C':
			if (p[1] == 'E') {
				if (version == 1 && data_length == 24) {
					/*
					 * CE extension comprises:
					 *   8 byte sector containing extension
					 *   8 byte offset w/in above sector
					 *   8 byte length of continuation
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2102,6 +2102,7 @@
     const unsigned char *p, const unsigned char *end)
 {
 	struct iso9660 *iso9660;
+	int entry_seen = 0;
 
 	iso9660 = (struct iso9660 *)(a->format->data);
 
@@ -2257,8 +2258,16 @@
 		}
 
 		p += p[2];
-	}
-	return (ARCHIVE_OK);
+		entry_seen = 1;
+	}
+
+	if (entry_seen)
+		return (ARCHIVE_OK);
+	else {
+		archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
+				  "Tried to parse Rockridge extensions, but none found");
+		return (ARCHIVE_WARN);
+	}
 }
 
 static int
```
