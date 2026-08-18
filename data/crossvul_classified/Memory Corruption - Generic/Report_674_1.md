# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 674_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `674_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 25-65 of the vulnerable file.

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winpr/crt.h>

#include <freerdp/codec/nsc.h>
#include <freerdp/codec/color.h>

#include "nsc_types.h"
#include "nsc_encode.h"

#include "nsc_sse2.h"

#ifndef NSC_INIT_SIMD
#define NSC_INIT_SIMD(_nsc_context) do { } while (0)
#endif

static void nsc_decode(NSC_CONTEXT* context)
{
	UINT16 x;
	UINT16 y;
	UINT16 rw = ROUND_UP_TO(context->width, 8);
	BYTE shift = context->ColorLossLevel - 1; /* colorloss recovery + YCoCg shift */
	BYTE* bmpdata = context->BitmapData;

	for (y = 0; y < context->height; y++)
	{
		const BYTE* yplane;
		const BYTE* coplane;
		const BYTE* cgplane;
		const BYTE* aplane = context->priv->PlaneBuffers[3] + y * context->width; /* A */

		if (context->ChromaSubsamplingLevel)
		{
			yplane = context->priv->PlaneBuffers[0] + y * rw; /* Y */
			coplane = context->priv->PlaneBuffers[1] + (y >> 1) * (rw >>
			          1); /* Co, supersampled */
			cgplane = context->priv->PlaneBuffers[2] + (y >> 1) * (rw >>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,13 +42,24 @@
 #define NSC_INIT_SIMD(_nsc_context) do { } while (0)
 #endif
 
-static void nsc_decode(NSC_CONTEXT* context)
+static BOOL nsc_decode(NSC_CONTEXT* context)
 {
 	UINT16 x;
 	UINT16 y;
-	UINT16 rw = ROUND_UP_TO(context->width, 8);
-	BYTE shift = context->ColorLossLevel - 1; /* colorloss recovery + YCoCg shift */
-	BYTE* bmpdata = context->BitmapData;
+	UINT16 rw;
+	BYTE shift;
+	BYTE* bmpdata;
+	size_t pos = 0;
+
+	if (!context)
+		return FALSE;
+
+	rw = ROUND_UP_TO(context->width, 8);
+	shift = context->ColorLossLevel - 1; /* colorloss recovery + YCoCg shift */
+	bmpdata = context->BitmapData;
+
+	if (!bmpdata)
+		return FALSE;
 
 	for (y = 0; y < context->height; y++)
 	{
@@ -80,6 +91,11 @@
 			INT16 r_val = y_val + co_val - cg_val;
 			INT16 g_val = y_val + cg_val;
 			INT16 b_val = y_val - co_val - cg_val;
+
+			if (pos + 4 > context->BitmapDataLength)
+				return FALSE;
+
+			pos += 4;
 			*bmpdata++ = MINMAX(b_val, 0, 0xFF);
 			*bmpdata++ = MINMAX(g_val, 0, 0xFF);
 			*bmpdata++ = MINMAX(r_val, 0, 0xFF);
@@ -90,9 +106,11 @@
 			aplane++;
 		}
 	}
-}
-
-static void nsc_rle_decode(BYTE* in, BYTE* out, UINT32 originalSize)
+
+	return TRUE;
+}
+
+static BOOL nsc_rle_decode(BYTE* in, BYTE* out, UINT32 outSize, UINT32 originalSize)
 {
 	UINT32 len;
 	UINT32 left;
@@ -105,6 +123,10 @@
 
 		if (left == 5)
 		{
+			if (outSize < 1)
+				return FALSE;
+
+			outSize--;
 			*out++ = value;
 			left--;
 		}
@@ -124,26 +146,42 @@
 				in += 4;
 			}
 
+			if (outSize < len)
+				return FALSE;
+
+			outSize -= len;
 			FillMemory(out, len, value);
 			out += len;
 			left -= len;
 		}
 		else
 		{
+			if (outSize < 1)
+				return FALSE;
+
+			outSize--;
 			*out++ = value;
 			left--;
 		}
 	}
 
-	*((UINT32*)out) = *((UINT32*)in);
-}
-
-static void nsc_rle_decompress_data(NSC_CONTEXT* context)
+	if ((outSize < 4) || (left < 4))
+		return FALSE;
+
+	memcpy(out, in, 4);
+	return TRUE;
+}
+
+static BOOL nsc_rle_decompress_data(NSC_CONTEXT* context)
 {
 	UINT16 i;
 	BYTE* rle;
 	UINT32 planeSize;
 	UINT32 originalSize;
+
+	if (!context)
+		return FALSE;
+
 	rle = context->Planes;
 
 	for (i = 0; i < 4; i++)
@@ -152,14 +190,30 @@
 		planeSize = context->PlaneByteCount[i];
 
 		if (planeSize == 0)
+		{
+			if (context->priv->PlaneBuffersLength < originalSize)
+				return FALSE;
+
 			FillMemory(context->priv->PlaneBuffers[i], originalSize, 0xFF);
+		}
 		else if (planeSize < originalSize)
-			nsc_rle_decode(rle, context->priv->PlaneBuffers[i], originalSize);
+		{
+			if (!nsc_rle_decode(rle, context->priv->PlaneBuffers[i], context->priv->PlaneBuffersLength,
+			                    originalSize))
+				return FALSE;
+		}
 		else
+		{
+			if (context->priv->PlaneBuffersLength < originalSize)
+				return FALSE;
+
 			CopyMemory(context->priv->PlaneBuffers[i], rle, originalSize);
+		}
 
 		rle += planeSize;
 	}
+
+	return TRUE;
 }
 
 static BOOL nsc_stream_initialize(NSC_CONTEXT* context, wStream* s)
@@ -396,13 +450,25 @@
 		return FALSE;
 
 	/* RLE decode */
-	PROFILER_ENTER(context->priv->prof_nsc_rle_decompress_data)
-	nsc_rle_decompress_data(context);
-	PROFILER_EXIT(context->priv->prof_nsc_rle_decompress_data)
+	{
+		BOOL rc;
+		PROFILER_ENTER(context->priv->prof_nsc_rle_decompress_data)
+		rc = nsc_rle_decompress_data(context);
+		PROFILER_EXIT(context->priv->prof_nsc_rle_decompress_data)
+
+		if (!rc)
+			return FALSE;
+	}
 	/* Colorloss recover, Chroma supersample and AYCoCg to ARGB Conversion in one step */
-	PROFILER_ENTER(context->priv->prof_nsc_decode)
-	context->decode(context);
-	PROFILER_EXIT(context->priv->prof_nsc_decode)
+	{
+		BOOL rc;
+		PROFILER_ENTER(context->priv->prof_nsc_decode)
+		rc = context->decode(context);
+		PROFILER_EXIT(context->priv->prof_nsc_decode)
+
+		if (!rc)
+			return FALSE;
+	}
 
 	if (!freerdp_image_copy(pDstData, DstFormat, nDstStride, nXDst, nYDst,
 	                        width, height, context->BitmapData,
```
