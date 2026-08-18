# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 671_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `671_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 27-70 of the vulnerable file.

#include <winpr/print.h>
#include <winpr/bitstream.h>

#include <freerdp/log.h>
#include <freerdp/codec/zgfx.h>

#define TAG FREERDP_TAG("codec")

/**
 * RDP8 Compressor Limits:
 *
 * Maximum number of uncompressed bytes in a single segment: 65535
 * Maximum match distance / minimum history size: 2500000 bytes.
 * Maximum number of segments: 65535
 * Maximum expansion of a segment (when compressed size exceeds uncompressed): 1000 bytes
 * Minimum match length: 3 bytes
 */

struct _ZGFX_TOKEN
{
	int prefixLength;
	int prefixCode;
	int valueBits;
	int tokenType;
	UINT32 valueBase;
};
typedef struct _ZGFX_TOKEN ZGFX_TOKEN;

static const ZGFX_TOKEN ZGFX_TOKEN_TABLE[] =
{
	// len code vbits type  vbase
	{  1,    0,   8,   0,           0 },    // 0
	{  5,   17,   5,   1,           0 },    // 10001
	{  5,   18,   7,   1,          32 },    // 10010
	{  5,   19,   9,   1,         160 },    // 10011
	{  5,   20,  10,   1,         672 },    // 10100
	{  5,   21,  12,   1,        1696 },    // 10101
	{  5,   24,   0,   0,  0x00       },    // 11000
	{  5,   25,   0,   0,  0x01       },    // 11001
	{  6,   44,  14,   1,        5792 },    // 101100
	{  6,   45,  15,   1,       22176 },    // 101101
	{  6,   52,   0,   0,  0x02       },    // 110100
	{  6,   53,   0,   0,  0x03       },    // 110101
	{  6,   54,   0,   0,  0xFF       },    // 110110
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,13 +44,33 @@
 
 struct _ZGFX_TOKEN
 {
-	int prefixLength;
-	int prefixCode;
-	int valueBits;
-	int tokenType;
+	UINT32 prefixLength;
+	UINT32 prefixCode;
+	UINT32 valueBits;
+	UINT32 tokenType;
 	UINT32 valueBase;
 };
 typedef struct _ZGFX_TOKEN ZGFX_TOKEN;
+
+struct _ZGFX_CONTEXT
+{
+	BOOL Compressor;
+
+	const BYTE* pbInputCurrent;
+	const BYTE* pbInputEnd;
+
+	UINT32 bits;
+	UINT32 cBitsRemaining;
+	UINT32 BitsCurrent;
+	UINT32 cBitsCurrent;
+
+	BYTE OutputBuffer[65536];
+	UINT32 OutputCount;
+
+	BYTE HistoryBuffer[2500000];
+	UINT32 HistoryIndex;
+	UINT32 HistoryBufferSize;
+};
 
 static const ZGFX_TOKEN ZGFX_TOKEN_TABLE[] =
 {
@@ -98,17 +118,26 @@
 	{ 0 }
 };
 
-#define zgfx_GetBits(_zgfx, _nbits) \
-	while (_zgfx->cBitsCurrent < _nbits) { \
-		_zgfx->BitsCurrent <<= 8; \
-		if (_zgfx->pbInputCurrent < _zgfx->pbInputEnd) \
-			_zgfx->BitsCurrent += *(_zgfx->pbInputCurrent)++; \
-		_zgfx->cBitsCurrent += 8; \
-	} \
-	_zgfx->cBitsRemaining -= _nbits; \
-	_zgfx->cBitsCurrent -= _nbits; \
-	_zgfx->bits = _zgfx->BitsCurrent >> _zgfx->cBitsCurrent; \
+static INLINE BOOL zgfx_GetBits(ZGFX_CONTEXT* _zgfx, UINT32 _nbits)
+{
+	if (!_zgfx)
+		return FALSE;
+
+	while (_zgfx->cBitsCurrent < _nbits)
+	{
+		_zgfx->BitsCurrent <<= 8;
+
+		if (_zgfx->pbInputCurrent < _zgfx->pbInputEnd)
+			_zgfx->BitsCurrent += *(_zgfx->pbInputCurrent)++;
+
+		_zgfx->cBitsCurrent += 8;
+	}
+
+	_zgfx->cBitsRemaining -= _nbits;
+	_zgfx->cBitsCurrent -= _nbits;
+	_zgfx->bits = _zgfx->BitsCurrent >> _zgfx->cBitsCurrent;
 	_zgfx->BitsCurrent &= ((1 << _zgfx->cBitsCurrent) - 1);
+}
 
 static void zgfx_history_buffer_ring_write(ZGFX_CONTEXT* zgfx, const BYTE* src, size_t count)
 {
@@ -193,7 +222,7 @@
 {
 	BYTE c;
 	BYTE flags;
-	int extra;
+	UINT32 extra = 0;
 	int opIndex;
 	int haveBits;
 	int inPrefix;
@@ -317,8 +346,8 @@
 {
 	int status = -1;
 	BYTE descriptor;
-
 	wStream* stream = Stream_New((BYTE*)pSrcData, SrcSize);
+
 	if (!stream)
 		return -1;
 
@@ -333,6 +362,7 @@
 			goto fail;
 
 		*ppDstData = NULL;
+
 		if (zgfx->OutputCount > 0)
 			*ppDstData = (BYTE*) malloc(zgfx->OutputCount);
 
@@ -349,6 +379,7 @@
 		UINT16 segmentCount;
 		UINT32 uncompressedSize;
 		BYTE* pConcatenated;
+		size_t used = 0;
 
 		if (Stream_GetRemainingLength(stream) < 6)
 			goto fail;
@@ -377,8 +408,15 @@
 			if (!zgfx_decompress_segment(zgfx, stream, segmentSize))
 				goto fail;
 
+			if (zgfx->OutputCount > UINT32_MAX - used)
+				goto fail;
+
+			if (used + zgfx->OutputCount > uncompressedSize)
+				goto fail;
+
 			CopyMemory(pConcatenated, zgfx->OutputBuffer, zgfx->OutputCount);
 			pConcatenated += zgfx->OutputCount;
+			used += zgfx->OutputCount;
 		}
 	}
 	else
```
