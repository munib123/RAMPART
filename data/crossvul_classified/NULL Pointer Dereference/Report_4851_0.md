# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4851_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4851_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 234-274 of the vulnerable file.


/******************************************************************************\
* Box input.
\******************************************************************************/

jp2_box_t *jp2_box_get(jas_stream_t *in)
{
	jp2_box_t *box;
	jp2_boxinfo_t *boxinfo;
	jas_stream_t *tmpstream;
	uint_fast32_t len;
	uint_fast64_t extlen;
	bool dataflag;

	box = 0;
	tmpstream = 0;

	if (!(box = jas_malloc(sizeof(jp2_box_t)))) {
		goto error;
	}
	box->ops = &jp2_boxinfo_unk.ops;
	if (jp2_getuint32(in, &len) || jp2_getuint32(in, &box->type)) {
		goto error;
	}
	boxinfo = jp2_boxinfolookup(box->type);
	box->info = boxinfo;
	box->ops = &boxinfo->ops;
	box->len = len;
	JAS_DBGLOG(10, (
	  "preliminary processing of JP2 box: type=%c%s%c (0x%08x); length=%d\n",
	  '"', boxinfo->name, '"', box->type, box->len
	  ));
	if (box->len == 1) {
		if (jp2_getuint64(in, &extlen)) {
			goto error;
		}
		if (extlen > 0xffffffffUL) {
			jas_eprintf("warning: cannot handle large 64-bit box length\n");
			extlen = 0xffffffffUL;
		}
		box->len = extlen;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -251,13 +251,16 @@
 	if (!(box = jas_malloc(sizeof(jp2_box_t)))) {
 		goto error;
 	}
+
+	// Mark the box data as never having been constructed
+	// so that we will not errantly attempt to destroy it later.
 	box->ops = &jp2_boxinfo_unk.ops;
+
 	if (jp2_getuint32(in, &len) || jp2_getuint32(in, &box->type)) {
 		goto error;
 	}
 	boxinfo = jp2_boxinfolookup(box->type);
 	box->info = boxinfo;
-	box->ops = &boxinfo->ops;
 	box->len = len;
 	JAS_DBGLOG(10, (
 	  "preliminary processing of JP2 box: type=%c%s%c (0x%08x); length=%d\n",
@@ -287,13 +290,14 @@
 			goto error;
 		}
 		if (jas_stream_copy(tmpstream, in, box->datalen)) {
-			// Mark the box data as never having been constructed
-			// so that we will not errantly attempt to destroy it later.
-			box->ops = &jp2_boxinfo_unk.ops;
 			jas_eprintf("cannot copy box data\n");
 			goto error;
 		}
 		jas_stream_rewind(tmpstream);
+
+		// From here onwards, the box data will need to be destroyed.
+		// So, initialize the box operations.
+		box->ops = &boxinfo->ops;
 
 		if (box->ops->getdata) {
 			if ((*box->ops->getdata)(box, tmpstream)) {
@@ -327,8 +331,8 @@
 	assert(boxinfo);
 
 	fprintf(out, "JP2 box: ");
-	fprintf(out, "type=%c%s%c (0x%08"PRIxFAST32"); length=%"PRIuFAST32"\n", '"', boxinfo->name,
-	  '"', box->type, box->len);
+	fprintf(out, "type=%c%s%c (0x%08"PRIxFAST32"); length=%"PRIuFAST32"\n", '"',
+	  boxinfo->name, '"', box->type, box->len);
 	if (box->ops->dumpdata) {
 		(*box->ops->dumpdata)(box, out);
 	}
```
