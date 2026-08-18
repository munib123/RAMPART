# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 277_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `277_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 181-221 of the vulnerable file.

    /* 4 bytes: length of unpacked file */
    if (hdr->headers & MSKWAJ_HDR_HASLENGTH) {
	if (sys->read(fh, &buf[0], 4) != 4) return MSPACK_ERR_READ;
	hdr->length = EndGetI32(&buf[0]);
    }

    /* 2 bytes: unknown purpose */
    if (hdr->headers & MSKWAJ_HDR_HASUNKNOWN1) {
	if (sys->read(fh, &buf[0], 2) != 2) return MSPACK_ERR_READ;
    }

    /* 2 bytes: length of section, then [length] bytes: unknown purpose */
    if (hdr->headers & MSKWAJ_HDR_HASUNKNOWN2) {
	if (sys->read(fh, &buf[0], 2) != 2) return MSPACK_ERR_READ;
	i = EndGetI16(&buf[0]);
	if (sys->seek(fh, (off_t)i, MSPACK_SYS_SEEK_CUR)) return MSPACK_ERR_SEEK;
    }

    /* filename and extension */
    if (hdr->headers & (MSKWAJ_HDR_HASFILENAME | MSKWAJ_HDR_HASFILEEXT)) {
	off_t pos = sys->tell(fh);
	char *fn = (char *) sys->alloc(sys, (size_t) 13);

	/* allocate memory for maximum length filename */
	if (! fn) return MSPACK_ERR_NOMEMORY;
	hdr->filename = fn;

	/* copy filename if present */
	if (hdr->headers & MSKWAJ_HDR_HASFILENAME) {
	    if (sys->read(fh, &buf[0], 9) != 9) return MSPACK_ERR_READ;
	    for (i = 0; i < 9; i++, fn++) if (!(*fn = buf[i])) break;
	    pos += (i < 9) ? i+1 : 9;
	    if (sys->seek(fh, pos, MSPACK_SYS_SEEK_START))
		return MSPACK_ERR_SEEK;
	}

	/* copy extension if present */
	if (hdr->headers & MSKWAJ_HDR_HASFILEEXT) {
	    *fn++ = '.';
	    if (sys->read(fh, &buf[0], 4) != 4) return MSPACK_ERR_READ;
	    for (i = 0; i < 4; i++, fn++) if (!(*fn = buf[i])) break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -198,30 +198,36 @@
 
     /* filename and extension */
     if (hdr->headers & (MSKWAJ_HDR_HASFILENAME | MSKWAJ_HDR_HASFILEEXT)) {
-	off_t pos = sys->tell(fh);
+	int len;
+	/* allocate memory for maximum length filename */
 	char *fn = (char *) sys->alloc(sys, (size_t) 13);
-
-	/* allocate memory for maximum length filename */
-	if (! fn) return MSPACK_ERR_NOMEMORY;
-	hdr->filename = fn;
+	if (!(hdr->filename = fn)) return MSPACK_ERR_NOMEMORY;
 
 	/* copy filename if present */
 	if (hdr->headers & MSKWAJ_HDR_HASFILENAME) {
-	    if (sys->read(fh, &buf[0], 9) != 9) return MSPACK_ERR_READ;
-	    for (i = 0; i < 9; i++, fn++) if (!(*fn = buf[i])) break;
-	    pos += (i < 9) ? i+1 : 9;
-	    if (sys->seek(fh, pos, MSPACK_SYS_SEEK_START))
+	    /* read and copy up to 9 bytes of a null terminated string */
+	    if ((len = sys->read(fh, &buf[0], 9)) < 2) return MSPACK_ERR_READ;
+	    for (i = 0; i < len; i++) if (!(*fn++ = buf[i])) break;
+	    /* if string was 9 bytes with no null terminator, reject it */
+	    if (i == 9 && buf[8] != '\0') return MSPACK_ERR_DATAFORMAT;
+	    /* seek to byte after string ended in file */
+	    if (sys->seek(fh, (off_t)(i + 1 - len), MSPACK_SYS_SEEK_CUR))
 		return MSPACK_ERR_SEEK;
+	    fn--; /* remove the null terminator */
 	}
 
 	/* copy extension if present */
 	if (hdr->headers & MSKWAJ_HDR_HASFILEEXT) {
 	    *fn++ = '.';
-	    if (sys->read(fh, &buf[0], 4) != 4) return MSPACK_ERR_READ;
-	    for (i = 0; i < 4; i++, fn++) if (!(*fn = buf[i])) break;
-	    pos += (i < 4) ? i+1 : 4;
-	    if (sys->seek(fh, pos, MSPACK_SYS_SEEK_START))
+	    /* read and copy up to 4 bytes of a null terminated string */
+	    if ((len = sys->read(fh, &buf[0], 4)) < 2) return MSPACK_ERR_READ;
+	    for (i = 0; i < len; i++) if (!(*fn++ = buf[i])) break;
+	    /* if string was 4 bytes with no null terminator, reject it */
+	    if (i == 4 && buf[3] != '\0') return MSPACK_ERR_DATAFORMAT;
+	    /* seek to byte after string ended in file */
+	    if (sys->seek(fh, (off_t)(i + 1 - len), MSPACK_SYS_SEEK_CUR))
 		return MSPACK_ERR_SEEK;
+	    fn--; /* remove the null terminator */
 	}
 	*fn = '\0';
     }
```
