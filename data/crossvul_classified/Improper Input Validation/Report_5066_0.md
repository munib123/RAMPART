# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5066_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5066_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 384-424 of the vulnerable file.

	if (h == NULL)
	    return (ARCHIVE_FATAL);
	if (archive_entry_copy_pathname_l(entry,
	    (const char *)h, namelength, sconv) != 0) {
		if (errno == ENOMEM) {
			archive_set_error(&a->archive, ENOMEM,
			    "Can't allocate memory for Pathname");
			return (ARCHIVE_FATAL);
		}
		archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
		    "Pathname can't be converted from %s to current locale.",
		    archive_string_conversion_charset_name(sconv));
		r = ARCHIVE_WARN;
	}
	cpio->entry_offset = 0;

	__archive_read_consume(a, namelength + name_pad);

	/* If this is a symlink, read the link contents. */
	if (archive_entry_filetype(entry) == AE_IFLNK) {
		h = __archive_read_ahead(a,
			(size_t)cpio->entry_bytes_remaining, NULL);
		if (h == NULL)
			return (ARCHIVE_FATAL);
		if (archive_entry_copy_symlink_l(entry, (const char *)h,
		    (size_t)cpio->entry_bytes_remaining, sconv) != 0) {
			if (errno == ENOMEM) {
				archive_set_error(&a->archive, ENOMEM,
				    "Can't allocate memory for Linkname");
				return (ARCHIVE_FATAL);
			}
			archive_set_error(&a->archive,
			    ARCHIVE_ERRNO_FILE_FORMAT,
			    "Linkname can't be converted from %s to "
			    "current locale.",
			    archive_string_conversion_charset_name(sconv));
			r = ARCHIVE_WARN;
		}
		__archive_read_consume(a, cpio->entry_bytes_remaining);
		cpio->entry_bytes_remaining = 0;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -401,6 +401,11 @@
 
 	/* If this is a symlink, read the link contents. */
 	if (archive_entry_filetype(entry) == AE_IFLNK) {
+		if (cpio->entry_bytes_remaining > 1024 * 1024) {
+			archive_set_error(&a->archive, ENOMEM,
+			    "Rejecting malformed cpio archive: symlink contents exceed 1 megabyte");
+			return (ARCHIVE_FATAL);
+		}
 		h = __archive_read_ahead(a,
 			(size_t)cpio->entry_bytes_remaining, NULL);
 		if (h == NULL)
```
