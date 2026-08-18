# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5400_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5400_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 330-370 of the vulnerable file.


	cmpt->type_ = JAS_IMAGE_CT_UNKNOWN;
	cmpt->tlx_ = tlx;
	cmpt->tly_ = tly;
	cmpt->hstep_ = hstep;
	cmpt->vstep_ = vstep;
	cmpt->width_ = width;
	cmpt->height_ = height;
	cmpt->prec_ = depth;
	cmpt->sgnd_ = sgnd;
	cmpt->stream_ = 0;
	cmpt->cps_ = (depth + 7) / 8;

	// Compute the number of samples in the image component, while protecting
	// against overflow.
	// size = cmpt->width_ * cmpt->height_ * cmpt->cps_;
	if (!jas_safe_size_mul(cmpt->width_, cmpt->height_, &size) ||
	  !jas_safe_size_mul(size, cmpt->cps_, &size)) {
		goto error;
	}
	cmpt->stream_ = (inmem) ? jas_stream_memopen(0, size) :
	  jas_stream_tmpfile();
	if (!cmpt->stream_) {
		goto error;
	}

	/* Zero the component data.  This isn't necessary, but it is
	convenient for debugging purposes. */
	/* Note: conversion of size - 1 to long can overflow */
	if (jas_stream_seek(cmpt->stream_, size - 1, SEEK_SET) < 0 ||
	  jas_stream_putc(cmpt->stream_, 0) == EOF ||
	  jas_stream_seek(cmpt->stream_, 0, SEEK_SET) < 0) {
		goto error;
	}

	return cmpt;

error:
	if (cmpt) {
		jas_image_cmpt_destroy(cmpt);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -347,7 +347,7 @@
 	  !jas_safe_size_mul(size, cmpt->cps_, &size)) {
 		goto error;
 	}
-	cmpt->stream_ = (inmem) ? jas_stream_memopen(0, size) :
+	cmpt->stream_ = (inmem) ? jas_stream_memopen2(0, size) :
 	  jas_stream_tmpfile();
 	if (!cmpt->stream_) {
 		goto error;
```
