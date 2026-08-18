# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3223_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3223_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 647-687 of the vulnerable file.

	return jas_stream_putc_macro(stream, c);
}

int jas_stream_ungetc(jas_stream_t *stream, int c)
{
	if (!stream->ptr_ || stream->ptr_ == stream->bufbase_) {
		return -1;
	}

	/* Reset the EOF indicator (since we now have at least one character
	  to read). */
	stream->flags_ &= ~JAS_STREAM_EOF;

	--stream->rwcnt_;
	--stream->ptr_;
	++stream->cnt_;
	*stream->ptr_ = c;
	return 0;
}

int jas_stream_read(jas_stream_t *stream, void *buf, int cnt)
{
	int n;
	int c;
	char *bufptr;

	JAS_DBGLOG(100, ("jas_stream_read(%p, %p, %d)\n", stream, buf, cnt));

	if (cnt < 0) {
		jas_deprecated("negative count for jas_stream_read");
	}

	bufptr = buf;

	n = 0;
	while (n < cnt) {
		if ((c = jas_stream_getc(stream)) == EOF) {
			return n;
		}
		*bufptr++ = c;
		++n;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -664,6 +664,7 @@
 	return 0;
 }
 
+/* FIXME integral type */
 int jas_stream_read(jas_stream_t *stream, void *buf, int cnt)
 {
 	int n;
@@ -690,6 +691,7 @@
 	return n;
 }
 
+/* FIXME integral type */
 int jas_stream_write(jas_stream_t *stream, const void *buf, int cnt)
 {
 	int n;
@@ -742,6 +744,7 @@
 	return 0;
 }
 
+/* FIXME integral type */
 char *jas_stream_gets(jas_stream_t *stream, char *buf, int bufsize)
 {
 	int c;
@@ -765,6 +768,7 @@
 	return buf;
 }
 
+/* FIXME integral type */
 int jas_stream_gobble(jas_stream_t *stream, int n)
 {
 	int m;
@@ -783,6 +787,7 @@
 	return n;
 }
 
+/* FIXME integral type */
 int jas_stream_pad(jas_stream_t *stream, int n, int c)
 {
 	int m;
@@ -885,6 +890,7 @@
 * Buffer initialization code.
 \******************************************************************************/
 
+/* FIXME integral type */
 static void jas_stream_initbuf(jas_stream_t *stream, int bufmode, char *buf,
   int bufsize)
 {
@@ -1060,6 +1066,7 @@
 	return openmode;
 }
 
+/* FIXME integral type */
 int jas_stream_copy(jas_stream_t *out, jas_stream_t *in, int n)
 {
 	int all;
@@ -1085,6 +1092,7 @@
 	return 0;
 }
 
+/* FIXME integral type */
 long jas_stream_setrwcount(jas_stream_t *stream, long rwcnt)
 {
 	int old;
@@ -1094,6 +1102,7 @@
 	return old;
 }
 
+/* FIXME integral type */
 int jas_stream_display(jas_stream_t *stream, FILE *fp, int n)
 {
 	unsigned char buf[16];
@@ -1168,6 +1177,7 @@
 * Memory stream object.
 \******************************************************************************/
 
+/* FIXME integral type */
 static int mem_read(jas_stream_obj_t *obj, char *buf, int cnt)
 {
 	ssize_t n;
@@ -1209,6 +1219,7 @@
 	return 0;
 }
 
+/* FIXME integral type */
 static int mem_write(jas_stream_obj_t *obj, char *buf, int cnt)
 {
 	size_t n;
@@ -1264,6 +1275,7 @@
 	return ret;
 }
 
+/* FIXME integral type */
 static long mem_seek(jas_stream_obj_t *obj, long offset, int origin)
 {
 	jas_stream_memobj_t *m = (jas_stream_memobj_t *)obj;
@@ -1310,6 +1322,7 @@
 * File stream object.
 \******************************************************************************/
 
+/* FIXME integral type */
 static int file_read(jas_stream_obj_t *obj, char *buf, int cnt)
 {
 	jas_stream_fileobj_t *fileobj;
@@ -1318,6 +1331,7 @@
 	return read(fileobj->fd, buf, cnt);
 }
 
+/* FIXME integral type */
 static int file_write(jas_stream_obj_t *obj, char *buf, int cnt)
 {
 	jas_stream_fileobj_t *fileobj;
@@ -1326,6 +1340,7 @@
 	return write(fileobj->fd, buf, cnt);
 }
 
+/* FIXME integral type */
 static long file_seek(jas_stream_obj_t *obj, long offset, int origin)
 {
 	jas_stream_fileobj_t *fileobj;
@@ -1352,6 +1367,7 @@
 * Stdio file stream object.
 \******************************************************************************/
 
+/* FIXME integral type */
 static int sfile_read(jas_stream_obj_t *obj, char *buf, int cnt)
 {
 	FILE *fp;
@@ -1367,6 +1383,7 @@
 	return result;
 }
 
+/* FIXME integral type */
 static int sfile_write(jas_stream_obj_t *obj, char *buf, int cnt)
 {
 	FILE *fp;
@@ -1377,6 +1394,7 @@
 	return (n != JAS_CAST(size_t, cnt)) ? (-1) : cnt;
 }
 
+/* FIXME integral type */
 static long sfile_seek(jas_stream_obj_t *obj, long offset, int origin)
 {
 	FILE *fp;
```
