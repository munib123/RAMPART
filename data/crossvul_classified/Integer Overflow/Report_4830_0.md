# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4830_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4830_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 192-232 of the vulnerable file.

	        (*fmt != GD2_FMT_TRUECOLOR_RAW) &&
	        (*fmt != GD2_FMT_TRUECOLOR_COMPRESSED)) {
		GD2_DBG (printf ("Bad data format: %d\n", *fmt));
		goto fail1;
	};


	/* # of chunks wide */
	if (gdGetWord (ncx, in) != 1) {
		goto fail1;
	};
	GD2_DBG (printf ("%d Chunks Wide\n", *ncx));

	/* # of chunks high */
	if (gdGetWord (ncy, in) != 1) {
		goto fail1;
	};
	GD2_DBG (printf ("%d Chunks vertically\n", *ncy));

	if (gd2_compressed (*fmt)) {
		nc = (*ncx) * (*ncy);

		GD2_DBG (printf ("Reading %d chunk index entries\n", nc));
		if (overflow2(sizeof(t_chunk_info), nc)) {
			goto fail1;
		}
		sidx = sizeof (t_chunk_info) * nc;
		if (sidx <= 0) {
			goto fail1;
		}

		cidx = gdCalloc (sidx, 1);
		if (cidx == NULL) {
			goto fail1;
		}
		for (i = 0; i < nc; i++) {
			if (gdGetInt (&cidx[i].offset, in) != 1) {
				goto fail2;
			};
			if (gdGetInt (&cidx[i].size, in) != 1) {
				goto fail2;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -209,6 +209,10 @@
 	GD2_DBG (printf ("%d Chunks vertically\n", *ncy));
 
 	if (gd2_compressed (*fmt)) {
+		if (*ncx <= 0 || *ncy <= 0 || *ncx > INT_MAX / *ncy) {
+			GD2_DBG(printf ("Illegal chunk counts: %d * %d\n", *ncx, *ncy));
+			goto fail1;
+		}
 		nc = (*ncx) * (*ncy);
 
 		GD2_DBG (printf ("Reading %d chunk index entries\n", nc));
```
