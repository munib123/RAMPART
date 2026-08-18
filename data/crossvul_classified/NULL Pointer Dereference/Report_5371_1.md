# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5371_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5371_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 138-178 of the vulnerable file.

		goto error;
	}
	jp2_box_destroy(box);
	box = 0;

	/* Get the second box.  This should be a FTYP box. */
	if (!(box = jp2_box_get(in))) {
		goto error;
	}
	if (box->type != JP2_BOX_FTYP) {
		jas_eprintf("expecting file type box\n");
		goto error;
	}
	jp2_box_destroy(box);
	box = 0;

	/* Get more boxes... */
	found = 0;
	while ((box = jp2_box_get(in))) {
		if (jas_getdbglevel() >= 1) {
			jas_eprintf("box type %s\n", box->info->name);
		}
		switch (box->type) {
		case JP2_BOX_JP2C:
			found = 1;
			break;
		case JP2_BOX_IHDR:
			if (!dec->ihdr) {
				dec->ihdr = box;
				box = 0;
			}
			break;
		case JP2_BOX_BPCC:
			if (!dec->bpcc) {
				dec->bpcc = box;
				box = 0;
			}
			break;
		case JP2_BOX_CDEF:
			if (!dec->cdef) {
				dec->cdef = box;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,7 +155,7 @@
 	found = 0;
 	while ((box = jp2_box_get(in))) {
 		if (jas_getdbglevel() >= 1) {
-			jas_eprintf("box type %s\n", box->info->name);
+			jas_eprintf("got box type %s\n", box->info->name);
 		}
 		switch (box->type) {
 		case JP2_BOX_JP2C:
```
