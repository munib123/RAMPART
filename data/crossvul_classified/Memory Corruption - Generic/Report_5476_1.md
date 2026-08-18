# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5476_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5476_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 17-68 of the vulnerable file.

 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
 * 
 * IN NO EVENT SHALL SAM LEFFLER OR SILICON GRAPHICS BE LIABLE FOR
 * ANY SPECIAL, INCIDENTAL, INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND,
 * OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER OR NOT ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF 
 * LIABILITY, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE 
 * OF THIS SOFTWARE.
 */

/*
 * TIFF Library.
 *
 * Predictor Tag Support (used by multiple codecs).
 */
#include "tiffiop.h"
#include "tif_predict.h"

#define	PredictorState(tif)	((TIFFPredictorState*) (tif)->tif_data)

static void horAcc8(TIFF* tif, uint8* cp0, tmsize_t cc);
static void horAcc16(TIFF* tif, uint8* cp0, tmsize_t cc);
static void horAcc32(TIFF* tif, uint8* cp0, tmsize_t cc);
static void swabHorAcc16(TIFF* tif, uint8* cp0, tmsize_t cc);
static void swabHorAcc32(TIFF* tif, uint8* cp0, tmsize_t cc);
static void horDiff8(TIFF* tif, uint8* cp0, tmsize_t cc);
static void horDiff16(TIFF* tif, uint8* cp0, tmsize_t cc);
static void horDiff32(TIFF* tif, uint8* cp0, tmsize_t cc);
static void swabHorDiff16(TIFF* tif, uint8* cp0, tmsize_t cc);
static void swabHorDiff32(TIFF* tif, uint8* cp0, tmsize_t cc);
static void fpAcc(TIFF* tif, uint8* cp0, tmsize_t cc);
static void fpDiff(TIFF* tif, uint8* cp0, tmsize_t cc);
static int PredictorDecodeRow(TIFF* tif, uint8* op0, tmsize_t occ0, uint16 s);
static int PredictorDecodeTile(TIFF* tif, uint8* op0, tmsize_t occ0, uint16 s);
static int PredictorEncodeRow(TIFF* tif, uint8* bp, tmsize_t cc, uint16 s);
static int PredictorEncodeTile(TIFF* tif, uint8* bp0, tmsize_t cc0, uint16 s);

static int
PredictorSetup(TIFF* tif)
{
	static const char module[] = "PredictorSetup";

	TIFFPredictorState* sp = PredictorState(tif);
	TIFFDirectory* td = &tif->tif_dir;

	switch (sp->predictor)		/* no differencing */
	{
		case PREDICTOR_NONE:
			return 1;
		case PREDICTOR_HORIZONTAL:
			if (td->td_bitspersample != 8
			    && td->td_bitspersample != 16
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,18 +34,18 @@
 
 #define	PredictorState(tif)	((TIFFPredictorState*) (tif)->tif_data)
 
-static void horAcc8(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void horAcc16(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void horAcc32(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void swabHorAcc16(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void swabHorAcc32(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void horDiff8(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void horDiff16(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void horDiff32(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void swabHorDiff16(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void swabHorDiff32(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void fpAcc(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void fpDiff(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int horAcc8(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int horAcc16(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int horAcc32(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int swabHorAcc16(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int swabHorAcc32(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int horDiff8(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int horDiff16(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int horDiff32(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int swabHorDiff16(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int swabHorDiff32(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int fpAcc(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int fpDiff(TIFF* tif, uint8* cp0, tmsize_t cc);
 static int PredictorDecodeRow(TIFF* tif, uint8* op0, tmsize_t occ0, uint16 s);
 static int PredictorDecodeTile(TIFF* tif, uint8* op0, tmsize_t occ0, uint16 s);
 static int PredictorEncodeRow(TIFF* tif, uint8* bp, tmsize_t cc, uint16 s);
@@ -273,13 +273,19 @@
 /* - when storing into the byte stream, we explicitly mask with 0xff so */
 /*   as to make icc -check=conversions happy (not necessary by the standard) */
 
-static void
+static int
 horAcc8(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	tmsize_t stride = PredictorState(tif)->stride;
 
 	unsigned char* cp = (unsigned char*) cp0;
-	assert((cc%stride)==0);
+    if((cc%stride)!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "horAcc8",
+                     "%s", "(cc%stride)!=0");
+        return 0;
+    }
+
 	if (cc > stride) {
 		/*
 		 * Pipeline the most common cases.
@@ -321,26 +327,32 @@
 			} while (cc>0);
 		}
 	}
-}
-
-static void
+	return 1;
+}
+
+static int
 swabHorAcc16(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	uint16* wp = (uint16*) cp0;
 	tmsize_t wc = cc / 2;
 
         TIFFSwabArrayOfShort(wp, wc);
-        horAcc16(tif, cp0, cc);
-}
-
-static void
+        return horAcc16(tif, cp0, cc);
+}
+
+static int
 horAcc16(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	tmsize_t stride = PredictorState(tif)->stride;
 	uint16* wp = (uint16*) cp0;
 	tmsize_t wc = cc / 2;
 
-	assert((cc%(2*stride))==0);
+    if((cc%(2*stride))!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "horAcc16",
+                     "%s", "cc%(2*stride))!=0");
+        return 0;
+    }
 
 	if (wc > stride) {
 		wc -= stride;
@@ -349,26 +361,32 @@
 			wc -= stride;
 		} while (wc > 0);
 	}
-}
-
-static void
+	return 1;
+}
+
+static int
 swabHorAcc32(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	uint32* wp = (uint32*) cp0;
 	tmsize_t wc = cc / 4;
 
         TIFFSwabArrayOfLong(wp, wc);
-	horAcc32(tif, cp0, cc);
-}
-
-static void
+	return horAcc32(tif, cp0, cc);
+}
+
+static int
 horAcc32(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	tmsize_t stride = PredictorState(tif)->stride;
 	uint32* wp = (uint32*) cp0;
 	tmsize_t wc = cc / 4;
 
-	assert((cc%(4*stride))==0);
+    if((cc%(4*stride))!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "horAcc32",
+                     "%s", "cc%(4*stride))!=0");
+        return 0;
+    }
 
 	if (wc > stride) {
 		wc -= stride;
@@ -377,12 +395,13 @@
 			wc -= stride;
 		} while (wc > 0);
 	}
+	return 1;
 }
 
 /*
  * Floating point predictor accumulation routine.
  */
-static void
+static int
 fpAcc(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	tmsize_t stride = PredictorState(tif)->stride;
@@ -392,10 +411,15 @@
 	uint8 *cp = (uint8 *) cp0;
 	uint8 *tmp = (uint8 *)_TIFFmalloc(cc);
 
-	assert((cc%(bps*stride))==0);
+    if(cc%(bps*stride)!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "fpAcc",
+                     "%s", "cc%(bps*stride))!=0");
+        return 0;
+    }
 
 	if (!tmp)
-		return;
+		return 0;
 
 	while (count > stride) {
 		REPEAT4(stride, cp[stride] =
@@ -417,6 +441,7 @@
 		}
 	}
 	_TIFFfree(tmp);
+    return 1;
 }
 
 /*
@@ -432,8 +457,7 @@
 	assert(sp->decodepfunc != NULL);  
 
 	if ((*sp->decoderow)(tif, op0, occ0, s)) {
-		(*sp->decodepfunc)(tif, op0, occ0);
-		return 1;
+		return (*sp->decodepfunc)(tif, op0, occ0);
 	} else
 		return 0;
 }
@@ -456,10 +480,16 @@
 	if ((*sp->decodetile)(tif, op0, occ0, s)) {
 		tmsize_t rowsize = sp->rowsize;
 		assert(rowsize > 0);
-		assert((occ0%rowsize)==0);
+		if((occ0%rowsize) !=0)
+        {
+            TIFFErrorExt(tif->tif_clientdata, "PredictorDecodeTile",
+                         "%s", "occ0%rowsize != 0");
+            return 0;
+        }
 		assert(sp->decodepfunc != NULL);
 		while (occ0 > 0) {
-			(*sp->decodepfunc)(tif, op0, rowsize);
+			if( !(*sp->decodepfunc)(tif, op0, rowsize) )
+                return 0;
 			occ0 -= rowsize;
 			op0 += rowsize;
 		}
@@ -468,14 +498,19 @@
 		return 0;
 }
 
-static void
+static int
 horDiff8(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	TIFFPredictorState* sp = PredictorState(tif);
 	tmsize_t stride = sp->stride;
 	unsigned char* cp = (unsigned char*) cp0;
 
-	assert((cc%stride)==0);
+    if((cc%stride)!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "horDiff8",
+                     "%s", "(cc%stride)!=0");
+        return 0;
+    }
 
 	if (cc > stride) {
 		cc -= stride;
@@ -513,9 +548,10 @@
 			} while ((cc -= stride) > 0);
 		}
 	}
-}
-
-static void
+	return 1;
+}
+
+static int
 horDiff16(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	TIFFPredictorState* sp = PredictorState(tif);
@@ -523,7 +559,12 @@
 	uint16 *wp = (uint16*) cp0;
 	tmsize_t wc = cc/2;
 
-	assert((cc%(2*stride))==0);
+    if((cc%(2*stride))!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "horDiff8",
+                     "%s", "(cc%(2*stride))!=0");
+        return 0;
+    }
 
 	if (wc > stride) {
 		wc -= stride;
@@ -533,20 +574,23 @@
 			wc -= stride;
 		} while (wc > 0);
 	}
-}
-
-static void
+	return 1;
+}
+
+static int
 swabHorDiff16(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
     uint16* wp = (uint16*) cp0;
     tmsize_t wc = cc / 2;
 
-    horDiff16(tif, cp0, cc);
+    if( !horDiff16(tif, cp0, cc) )
+        return 0;
 
     TIFFSwabArrayOfShort(wp, wc);
-}
-
-static void
+    return 1;
+}
+
+static int
 horDiff32(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	TIFFPredictorState* sp = PredictorState(tif);
@@ -554,7 +598,12 @@
 	uint32 *wp = (uint32*) cp0;
 	tmsize_t wc = cc/4;
 
-	assert((cc%(4*stride))==0);
+    if((cc%(4*stride))!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "horDiff32",
+                     "%s", "(cc%(4*stride))!=0");
+        return 0;
+    }
 
 	if (wc > stride) {
 		wc -= stride;
@@ -564,23 +613,26 @@
 			wc -= stride;
 		} while (wc > 0);
 	}
-}
-
-static void
+	return 1;
+}
+
+static int
 swabHorDiff32(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
     uint32* wp = (uint32*) cp0;
     tmsize_t wc = cc / 4;
 
-    horDiff32(tif, cp0, cc);
+    if( !horDiff32(tif, cp0, cc) )
+        return 0;
 
     TIFFSwabArrayOfLong(wp, wc);
+    return 1;
 }
 
 /*
  * Floating point predictor differencing routine.
  */
-static void
+static int
 fpDiff(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	tmsize_t stride = PredictorState(tif)->stride;
@@ -590,10 +642,14 @@
 	uint8 *cp = (uint8 *) cp0;
 	uint8 *tmp = (uint8 *)_TIFFmalloc(cc);
 
-	assert((cc%(bps*stride))==0);
-
+    if((cc%(bps*stride))!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "fpDiff",
... (diff truncated)
```
