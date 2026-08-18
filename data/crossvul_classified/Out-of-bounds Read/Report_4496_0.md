# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4496_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4496_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 184-224 of the vulnerable file.

			fInsertFgPel = TRUE;
			continue;
		}

		/* For any of the other run-types a follow-on background run
		    order does not need a foreground pel inserted. */
		fInsertFgPel = FALSE;

		switch (code)
		{
			/* Handle Foreground Run Orders. */
			case REGULAR_FG_RUN:
			case MEGA_MEGA_FG_RUN:
			case LITE_SET_FG_FG_RUN:
			case MEGA_MEGA_SET_FG_RUN:
				runLength = ExtractRunLength(code, pbSrc, &advance);
				pbSrc = pbSrc + advance;

				if (code == LITE_SET_FG_FG_RUN || code == MEGA_MEGA_SET_FG_RUN)
				{
					SRCREADPIXEL(fgPel, pbSrc);
					SRCNEXTPIXEL(pbSrc);
				}

				if (!ENSURE_CAPACITY(pbDest, pbDestEnd, runLength))
					return FALSE;

				if (fFirstLine)
				{
					UNROLL(runLength, {
						DESTWRITEPIXEL(pbDest, fgPel);
						DESTNEXTPIXEL(pbDest);
					});
				}
				else
				{
					UNROLL(runLength, {
						DESTREADPIXEL(temp, pbDest - rowDelta);
						DESTWRITEPIXEL(pbDest, temp ^ fgPel);
						DESTNEXTPIXEL(pbDest);
					});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -201,6 +201,8 @@
 
 				if (code == LITE_SET_FG_FG_RUN || code == MEGA_MEGA_SET_FG_RUN)
 				{
+					if (pbSrc >= pbEnd)
+						return FALSE;
 					SRCREADPIXEL(fgPel, pbSrc);
 					SRCNEXTPIXEL(pbSrc);
 				}
@@ -231,8 +233,12 @@
 			case MEGA_MEGA_DITHERED_RUN:
 				runLength = ExtractRunLength(code, pbSrc, &advance);
 				pbSrc = pbSrc + advance;
+				if (pbSrc >= pbEnd)
+					return FALSE;
 				SRCREADPIXEL(pixelA, pbSrc);
 				SRCNEXTPIXEL(pbSrc);
+				if (pbSrc >= pbEnd)
+					return FALSE;
 				SRCREADPIXEL(pixelB, pbSrc);
 				SRCNEXTPIXEL(pbSrc);
 
@@ -252,6 +258,8 @@
 			case MEGA_MEGA_COLOR_RUN:
 				runLength = ExtractRunLength(code, pbSrc, &advance);
 				pbSrc = pbSrc + advance;
+				if (pbSrc >= pbEnd)
+					return FALSE;
 				SRCREADPIXEL(pixelA, pbSrc);
 				SRCNEXTPIXEL(pbSrc);
 
@@ -272,6 +280,8 @@
 				runLength = ExtractRunLength(code, pbSrc, &advance);
 				pbSrc = pbSrc + advance;
 
+				if (pbSrc >= pbEnd)
+					return FALSE;
 				if (code == LITE_SET_FG_FGBG_IMAGE || code == MEGA_MEGA_SET_FGBG_IMAGE)
 				{
 					SRCREADPIXEL(fgPel, pbSrc);
@@ -338,6 +348,8 @@
 					return FALSE;
 
 				UNROLL(runLength, {
+					if (pbSrc >= pbEnd)
+						return FALSE;
 					SRCREADPIXEL(temp, pbSrc);
 					SRCNEXTPIXEL(pbSrc);
 					DESTWRITEPIXEL(pbDest, temp);
```
