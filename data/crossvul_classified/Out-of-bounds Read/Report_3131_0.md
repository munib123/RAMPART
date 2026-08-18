# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3131_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3131_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 906-946 of the vulnerable file.

			goto invalid;/* Invalid filename. */
	}
	archive_strncpy(&lha->filename, p + H1_FILE_NAME_OFFSET, namelen);
	lha->crc = archive_le16dec(p + H1_FILE_NAME_OFFSET + namelen);
	lha->setflag |= CRC_IS_SET;

	sum_calculated = lha_calcsum(0, p, 2, lha->header_size - 2);
	/* Consume used bytes but not include `next header size' data
	 * since it will be consumed in lha_read_file_extended_header(). */
	__archive_read_consume(a, lha->header_size - 2);

	/* Read extended headers */
	err2 = lha_read_file_extended_header(a, lha, NULL, 2,
	    (size_t)(lha->compsize + 2), &extdsize);
	if (err2 < ARCHIVE_WARN)
		return (err2);
	if (err2 < err)
		err = err2;
	/* Get a real compressed file size. */
	lha->compsize -= extdsize - 2;

	if (sum_calculated != headersum) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "LHa header sum error");
		return (ARCHIVE_FATAL);
	}
	return (err);
invalid:
	archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
	    "Invalid LHa header");
	return (ARCHIVE_FATAL);
}

/*
 * Header 2 format
 *
 * +0              +2               +7                  +11               +15
 * +---------------+----------------+-------------------+-----------------+
 * |header size(*1)|compression type|compressed size(*2)|uncompressed size|
 * +---------------+----------------+-------------------+-----------------+
 *  <--------------------------------(*1)---------------------------------*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -923,6 +923,9 @@
 		err = err2;
 	/* Get a real compressed file size. */
 	lha->compsize -= extdsize - 2;
+
+	if (lha->compsize < 0)
+		goto invalid;	/* Invalid compressed file size */
 
 	if (sum_calculated != headersum) {
 		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
```
