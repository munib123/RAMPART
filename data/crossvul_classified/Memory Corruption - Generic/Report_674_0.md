# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 674_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `674_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 60-101 of the vulnerable file.

typedef struct _NSC_CONTEXT NSC_CONTEXT;

struct _NSC_CONTEXT
{
	UINT32 OrgByteCount[4];
	UINT32 format;
	UINT16 width;
	UINT16 height;
	BYTE* BitmapData;
	UINT32 BitmapDataLength;

	BYTE* Planes;
	UINT32 PlaneByteCount[4];
	UINT32 ColorLossLevel;
	UINT32 ChromaSubsamplingLevel;
	BOOL DynamicColorFidelity;

	/* color palette allocated by the application */
	const BYTE* palette;

	void (*decode)(NSC_CONTEXT* context);
	void (*encode)(NSC_CONTEXT* context, const BYTE* BitmapData,
	               UINT32 rowstride);

	NSC_CONTEXT_PRIV* priv;
};

FREERDP_API BOOL nsc_context_set_pixel_format(NSC_CONTEXT* context,
        UINT32 pixel_format);
FREERDP_API BOOL nsc_process_message(NSC_CONTEXT* context, UINT16 bpp,
                                     UINT32 width, UINT32 height,
                                     const BYTE* data, UINT32 length,
                                     BYTE* pDstData, UINT32 DstFormat,
                                     UINT32 nDstStride, UINT32 nXDst, UINT32 nYDst,
                                     UINT32 nWidth, UINT32 nHeight, UINT32 flip);
FREERDP_API BOOL nsc_compose_message(NSC_CONTEXT* context, wStream* s,
                                     const BYTE* bmpdata,
                                     UINT32 width, UINT32 height, UINT32 rowstride);

FREERDP_API NSC_MESSAGE* nsc_encode_messages(NSC_CONTEXT* context,
        const BYTE* data,
        UINT32 x, UINT32 y,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,8 +77,8 @@
 	/* color palette allocated by the application */
 	const BYTE* palette;
 
-	void (*decode)(NSC_CONTEXT* context);
-	void (*encode)(NSC_CONTEXT* context, const BYTE* BitmapData,
+	BOOL (*decode)(NSC_CONTEXT* context);
+	BOOL (*encode)(NSC_CONTEXT* context, const BYTE* BitmapData,
 	               UINT32 rowstride);
 
 	NSC_CONTEXT_PRIV* priv;
```
