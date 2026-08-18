# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 674_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `674_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 34-74 of the vulnerable file.


#include "nsc_types.h"
#include "nsc_encode.h"

static BOOL nsc_context_initialize_encode(NSC_CONTEXT* context)
{
	int i;
	UINT32 length;
	UINT32 tempWidth;
	UINT32 tempHeight;
	tempWidth = ROUND_UP_TO(context->width, 8);
	tempHeight = ROUND_UP_TO(context->height, 2);
	/* The maximum length a decoded plane can reach in all cases */
	length = tempWidth * tempHeight + 16;

	if (length > context->priv->PlaneBuffersLength)
	{
		for (i = 0; i < 5; i++)
		{
			BYTE* tmp = (BYTE*) realloc(context->priv->PlaneBuffers[i], length);
			if (!tmp)
				goto fail;

			context->priv->PlaneBuffers[i] = tmp;
		}

		context->priv->PlaneBuffersLength = length;
	}

	if (context->ChromaSubsamplingLevel)
	{
		context->OrgByteCount[0] = tempWidth * context->height;
		context->OrgByteCount[1] = tempWidth * tempHeight / 4;
		context->OrgByteCount[2] = tempWidth * tempHeight / 4;
		context->OrgByteCount[3] = context->width * context->height;
	}
	else
	{
		context->OrgByteCount[0] = context->width * context->height;
		context->OrgByteCount[1] = context->width * context->height;
		context->OrgByteCount[2] = context->width * context->height;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,6 +51,7 @@
 		for (i = 0; i < 5; i++)
 		{
 			BYTE* tmp = (BYTE*) realloc(context->priv->PlaneBuffers[i], length);
+
 			if (!tmp)
 				goto fail;
 
@@ -87,7 +88,7 @@
 	return FALSE;
 }
 
-static void nsc_encode_argb_to_aycocg(NSC_CONTEXT* context, const BYTE* data,
+static BOOL nsc_encode_argb_to_aycocg(NSC_CONTEXT* context, const BYTE* data,
                                       UINT32 scanline)
 {
 	UINT16 x;
@@ -104,9 +105,19 @@
 	INT16 b_val;
 	BYTE a_val;
 	UINT32 tempWidth;
+
+	if (!context || data || (scanline == 0))
+		return FALSE;
+
 	tempWidth = ROUND_UP_TO(context->width, 8);
 	rw = (context->ChromaSubsamplingLevel ? tempWidth : context->width);
 	ccl = context->ColorLossLevel;
+
+	if (context->priv->PlaneBuffersLength < rw * scanline)
+		return FALSE;
+
+	if (rw < scanline * 2)
+		return FALSE;
 
 	for (y = 0; y < context->height; y++)
 	{
@@ -242,31 +253,37 @@
 		CopyMemory(coplane, coplane - rw, rw);
 		CopyMemory(cgplane, cgplane - rw, rw);
 	}
-}
-
-static void nsc_encode_subsampling(NSC_CONTEXT* context)
+
+	return TRUE;
+}
+
+static BOOL nsc_encode_subsampling(NSC_CONTEXT* context)
 {
 	UINT16 x;
 	UINT16 y;
-	BYTE* co_dst;
-	BYTE* cg_dst;
-	INT8* co_src0;
-	INT8* co_src1;
-	INT8* cg_src0;
-	INT8* cg_src1;
 	UINT32 tempWidth;
 	UINT32 tempHeight;
+
+	if (!context)
+		return FALSE;
+
 	tempWidth = ROUND_UP_TO(context->width, 8);
 	tempHeight = ROUND_UP_TO(context->height, 2);
 
+	if (tempHeight == 0)
+		return FALSE;
+
+	if (tempWidth > context->priv->PlaneBuffersLength / tempHeight)
+		return FALSE;
+
 	for (y = 0; y < tempHeight >> 1; y++)
 	{
-		co_dst = context->priv->PlaneBuffers[1] + y * (tempWidth >> 1);
-		cg_dst = context->priv->PlaneBuffers[2] + y * (tempWidth >> 1);
-		co_src0 = (INT8*) context->priv->PlaneBuffers[1] + (y << 1) * tempWidth;
-		co_src1 = co_src0 + tempWidth;
-		cg_src0 = (INT8*) context->priv->PlaneBuffers[2] + (y << 1) * tempWidth;
-		cg_src1 = cg_src0 + tempWidth;
+		BYTE* co_dst = context->priv->PlaneBuffers[1] + y * (tempWidth >> 1);
+		BYTE* cg_dst = context->priv->PlaneBuffers[2] + y * (tempWidth >> 1);
+		const INT8* co_src0 = (INT8*) context->priv->PlaneBuffers[1] + (y << 1) * tempWidth;
+		const INT8* co_src1 = co_src0 + tempWidth;
+		const INT8* cg_src0 = (INT8*) context->priv->PlaneBuffers[2] + (y << 1) * tempWidth;
+		const INT8* cg_src1 = cg_src0 + tempWidth;
 
 		for (x = 0; x < tempWidth >> 1; x++)
 		{
@@ -280,19 +297,28 @@
 			cg_src1 += 2;
 		}
 	}
-}
-
-void nsc_encode(NSC_CONTEXT* context, const BYTE* bmpdata, UINT32 rowstride)
-{
-	nsc_encode_argb_to_aycocg(context, bmpdata, rowstride);
+
+	return TRUE;
+}
+
+BOOL nsc_encode(NSC_CONTEXT* context, const BYTE* bmpdata, UINT32 rowstride)
+{
+	if (!context || !bmpdata || (rowstride == 0))
+		return FALSE;
+
+	if (!nsc_encode_argb_to_aycocg(context, bmpdata, rowstride))
+		return FALSE;
 
 	if (context->ChromaSubsamplingLevel)
 	{
-		nsc_encode_subsampling(context);
-	}
-}
-
-static UINT32 nsc_rle_encode(BYTE* in, BYTE* out, UINT32 originalSize)
+		if (!nsc_encode_subsampling(context))
+			return FALSE;
+	}
+
+	return TRUE;
+}
+
+static UINT32 nsc_rle_encode(const BYTE* in, BYTE* out, UINT32 originalSize)
 {
 	UINT32 left;
 	UINT32 runlength = 1;
```
