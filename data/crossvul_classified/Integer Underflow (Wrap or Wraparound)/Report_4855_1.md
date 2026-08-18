# CrossVul Fix Pair: Integer Underflow (Wrap or Wraparound) in c
**Pair ID:** 4855_1
**Vulnerability Class:** Integer Underflow (Wrap or Wraparound)
**CWE:** CWE-191
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4855_1`)

## Vulnerability Information & PoC

## Description
Integer Underflow (Wrap or Wraparound) - This can happen in signed and unsigned cases.

## Vulnerable Code
```c
Lines 968-1008 of the vulnerable file.

		    TIFFFileName(in), TIFFCurrentDirectory(in));
		return 0;
	}

}


/*
 * Strip -> strip for change in encoding.
 */
DECLAREcpFunc(cpDecodedStrips)
{
	tsize_t stripsize  = TIFFStripSize(in);
	tdata_t buf = _TIFFmalloc(stripsize);

	(void) imagewidth; (void) spp;
	if (buf) {
		tstrip_t s, ns = TIFFNumberOfStrips(in);
		uint32 row = 0;
		_TIFFmemset(buf, 0, stripsize);
		for (s = 0; s < ns; s++) {
			tsize_t cc = (row + rowsperstrip > imagelength) ?
			    TIFFVStripSize(in, imagelength - row) : stripsize;
			if (TIFFReadEncodedStrip(in, s, buf, cc) < 0
			    && !ignore) {
				TIFFError(TIFFFileName(in),
				    "Error, can't read strip %lu",
				    (unsigned long) s);
				goto bad;
			}
			if (TIFFWriteEncodedStrip(out, s, buf, cc) < 0) {
				TIFFError(TIFFFileName(out),
				    "Error, can't write strip %lu",
				    (unsigned long) s);
				goto bad;
			}
			row += rowsperstrip;
		}
		_TIFFfree(buf);
		return 1;
	} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -985,7 +985,7 @@
 		tstrip_t s, ns = TIFFNumberOfStrips(in);
 		uint32 row = 0;
 		_TIFFmemset(buf, 0, stripsize);
-		for (s = 0; s < ns; s++) {
+		for (s = 0; s < ns && row < imagelength; s++) {
 			tsize_t cc = (row + rowsperstrip > imagelength) ?
 			    TIFFVStripSize(in, imagelength - row) : stripsize;
 			if (TIFFReadEncodedStrip(in, s, buf, cc) < 0
```
