# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 4987_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4987_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 148-188 of the vulnerable file.

	if (gdGetWord (ncy, in) != 1) {
		goto fail1;
	};
	GD2_DBG (printf ("%d Chunks vertically\n", *ncy));

	if (gd2_compressed (*fmt)) {
		nc = (*ncx) * (*ncy);
		GD2_DBG (printf ("Reading %d chunk index entries\n", nc));
		sidx = sizeof (t_chunk_info) * nc;
		cidx = gdCalloc (sidx, 1);
		if (!cidx) {
			goto fail1;
		}
		for (i = 0; i < nc; i++) {
			if (gdGetInt (&cidx[i].offset, in) != 1) {
				goto fail2;
			};
			if (gdGetInt (&cidx[i].size, in) != 1) {
				goto fail2;
			};
		};
		*chunkIdx = cidx;
	};

	GD2_DBG (printf ("gd2 header complete\n"));

	return 1;
fail2:
	gdFree(cidx);
fail1:
	return 0;
}

static gdImagePtr
_gd2CreateFromFile (gdIOCtxPtr in, int *sx, int *sy,
                    int *cs, int *vers, int *fmt,
                    int *ncx, int *ncy, t_chunk_info ** cidx)
{
	gdImagePtr im;

	if (_gd2GetHeader (in, sx, sy, cs, vers, fmt, ncx, ncy, cidx) != 1) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -165,6 +165,8 @@
 			if (gdGetInt (&cidx[i].size, in) != 1) {
 				goto fail2;
 			};
+			if (cidx[i].offset < 0 || cidx[i].size < 0)
+				goto fail2;
 		};
 		*chunkIdx = cidx;
 	};
```
