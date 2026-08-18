# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 5479_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5479_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 781-821 of the vulnerable file.

            
	return (1);
}

/*
 * Internal version of TIFFFlushData that can be
 * called by ``encodestrip routines'' w/o concern
 * for infinite recursion.
 */
int
TIFFFlushData1(TIFF* tif)
{
	if (tif->tif_rawcc > 0 && tif->tif_flags & TIFF_BUF4WRITE ) {
		if (!isFillOrder(tif, tif->tif_dir.td_fillorder) &&
		    (tif->tif_flags & TIFF_NOBITREV) == 0)
			TIFFReverseBits((uint8*)tif->tif_rawdata,
			    tif->tif_rawcc);
		if (!TIFFAppendToStrip(tif,
		    isTiled(tif) ? tif->tif_curtile : tif->tif_curstrip,
		    tif->tif_rawdata, tif->tif_rawcc))
			return (0);
		tif->tif_rawcc = 0;
		tif->tif_rawcp = tif->tif_rawdata;
	}
	return (1);
}

/*
 * Set the current write offset.  This should only be
 * used to set the offset to a known previous location
 * (very carefully), or to 0 so that the next write gets
 * appended to the end of the file.
 */
void
TIFFSetWriteOffset(TIFF* tif, toff_t off)
{
	tif->tif_curoff = off;
}

/* vim: set ts=8 sts=8 sw=8 noet: */
/*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -798,7 +798,14 @@
 		if (!TIFFAppendToStrip(tif,
 		    isTiled(tif) ? tif->tif_curtile : tif->tif_curstrip,
 		    tif->tif_rawdata, tif->tif_rawcc))
+        {
+            /* We update those variables even in case of error since there's */
+            /* code that doesn't really check the return code of this */
+            /* function */
+            tif->tif_rawcc = 0;
+            tif->tif_rawcp = tif->tif_rawdata;
 			return (0);
+        }
 		tif->tif_rawcc = 0;
 		tif->tif_rawcp = tif->tif_rawdata;
 	}
```
