# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1984_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1984_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 215-255 of the vulnerable file.

	if (!found) {
		jas_eprintf("error: no code stream found\n");
		goto error;
	}

	if (!(dec->image = jpc_decode(in, optstr))) {
		jas_eprintf("error: cannot decode code stream\n");
		goto error;
	}

	/* An IHDR box must be present. */
	if (!dec->ihdr) {
		jas_eprintf("error: missing IHDR box\n");
		goto error;
	}

	/* Does the number of components indicated in the IHDR box match
	  the value specified in the code stream? */
	if (dec->ihdr->data.ihdr.numcmpts != JAS_CAST(jas_uint,
	  jas_image_numcmpts(dec->image))) {
		jas_eprintf("warning: number of components mismatch\n");
	}

	/* At least one component must be present. */
	if (!jas_image_numcmpts(dec->image)) {
		jas_eprintf("error: no components\n");
		goto error;
	}

	/* Determine if all components have the same data type. */
	samedtype = true;
	dtype = jas_image_cmptdtype(dec->image, 0);
	for (i = 1; i < JAS_CAST(jas_uint, jas_image_numcmpts(dec->image)); ++i) {
		if (jas_image_cmptdtype(dec->image, i) != dtype) {
			samedtype = false;
			break;
		}
	}

	/* Is the component data type indicated in the IHDR box consistent
	  with the data in the code stream? */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -232,7 +232,8 @@
 	  the value specified in the code stream? */
 	if (dec->ihdr->data.ihdr.numcmpts != JAS_CAST(jas_uint,
 	  jas_image_numcmpts(dec->image))) {
-		jas_eprintf("warning: number of components mismatch\n");
+		jas_eprintf("error: number of components mismatch (IHDR)\n");
+		goto error;
 	}
 
 	/* At least one component must be present. */
@@ -255,7 +256,8 @@
 	  with the data in the code stream? */
 	if ((samedtype && dec->ihdr->data.ihdr.bpc != JP2_DTYPETOBPC(dtype)) ||
 	  (!samedtype && dec->ihdr->data.ihdr.bpc != JP2_IHDR_BPCNULL)) {
-		jas_eprintf("warning: component data type mismatch (IHDR)\n");
+		jas_eprintf("error: component data type mismatch (IHDR)\n");
+		goto error;
 	}
 
 	/* Is the compression type supported? */
@@ -267,9 +269,10 @@
 	if (dec->bpcc) {
 		/* Is the number of components indicated in the BPCC box
 		  consistent with the code stream data? */
-		if (dec->bpcc->data.bpcc.numcmpts != JAS_CAST(jas_uint, jas_image_numcmpts(
-		  dec->image))) {
-			jas_eprintf("warning: number of components mismatch\n");
+		if (dec->bpcc->data.bpcc.numcmpts !=
+		  JAS_CAST(jas_uint, jas_image_numcmpts(dec->image))) {
+			jas_eprintf("error: number of components mismatch (BPCC)\n");
+			goto error;
 		}
 		/* Is the component data type information indicated in the BPCC
 		  box consistent with the code stream data? */
@@ -278,7 +281,8 @@
 			  ++i) {
 				if (jas_image_cmptdtype(dec->image, i) !=
 				  JP2_BPCTODTYPE(dec->bpcc->data.bpcc.bpcs[i])) {
-					jas_eprintf("warning: component data type mismatch (BPCC)\n");
+					jas_eprintf("error: component data type mismatch (BPCC)\n");
+						goto error;
 				}
 			}
 		} else {
```
