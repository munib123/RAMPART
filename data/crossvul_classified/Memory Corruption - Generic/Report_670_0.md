# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 670_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `670_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 120-160 of the vulnerable file.


static INLINE BOOL zgfx_GetBits(ZGFX_CONTEXT* _zgfx, UINT32 _nbits)
{
	if (!_zgfx)
		return FALSE;

	while (_zgfx->cBitsCurrent < _nbits)
	{
		_zgfx->BitsCurrent <<= 8;

		if (_zgfx->pbInputCurrent < _zgfx->pbInputEnd)
			_zgfx->BitsCurrent += *(_zgfx->pbInputCurrent)++;

		_zgfx->cBitsCurrent += 8;
	}

	_zgfx->cBitsRemaining -= _nbits;
	_zgfx->cBitsCurrent -= _nbits;
	_zgfx->bits = _zgfx->BitsCurrent >> _zgfx->cBitsCurrent;
	_zgfx->BitsCurrent &= ((1 << _zgfx->cBitsCurrent) - 1);
}

static void zgfx_history_buffer_ring_write(ZGFX_CONTEXT* zgfx, const BYTE* src, size_t count)
{
	UINT32 front;

	if (count <= 0)
		return;

	if (count > zgfx->HistoryBufferSize)
	{
		const size_t residue = count - zgfx->HistoryBufferSize;
		count = zgfx->HistoryBufferSize;
		src += residue;
		zgfx->HistoryIndex = (zgfx->HistoryIndex + residue) % zgfx->HistoryBufferSize;
	}

	if (zgfx->HistoryIndex + count <= zgfx->HistoryBufferSize)
	{
		CopyMemory(&(zgfx->HistoryBuffer[zgfx->HistoryIndex]), src, count);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -137,6 +137,7 @@
 	_zgfx->cBitsCurrent -= _nbits;
 	_zgfx->bits = _zgfx->BitsCurrent >> _zgfx->cBitsCurrent;
 	_zgfx->BitsCurrent &= ((1 << _zgfx->cBitsCurrent) - 1);
+	return TRUE;
 }
 
 static void zgfx_history_buffer_ring_write(ZGFX_CONTEXT* zgfx, const BYTE* src, size_t count)
@@ -229,9 +230,15 @@
 	UINT32 count;
 	UINT32 distance;
 	BYTE* pbSegment;
-	size_t cbSegment = segmentSize - 1;
-
-	if ((Stream_GetRemainingLength(stream) < segmentSize) || (segmentSize < 1))
+	size_t cbSegment;
+
+	if (!zgfx || !stream)
+		return FALSE;
+
+	cbSegment = segmentSize - 1;
+
+	if ((Stream_GetRemainingLength(stream) < segmentSize) || (segmentSize < 1) ||
+	    (segmentSize > UINT32_MAX))
 		return FALSE;
 
 	Stream_Read_UINT8(stream, flags); /* header (1 byte) */
@@ -242,6 +249,10 @@
 	if (!(flags & PACKET_COMPRESSED))
 	{
 		zgfx_history_buffer_ring_write(zgfx, pbSegment, cbSegment);
+
+		if (cbSegment > sizeof(zgfx->OutputBuffer))
+			return FALSE;
+
 		CopyMemory(zgfx->OutputBuffer, pbSegment, cbSegment);
 		zgfx->OutputCount = cbSegment;
 		return TRUE;
@@ -279,6 +290,9 @@
 
 					if (++zgfx->HistoryIndex == zgfx->HistoryBufferSize)
 						zgfx->HistoryIndex = 0;
+
+					if (zgfx->OutputCount >= sizeof(zgfx->OutputBuffer))
+						return FALSE;
 
 					zgfx->OutputBuffer[zgfx->OutputCount++] = c;
 				}
@@ -312,6 +326,9 @@
 							zgfx_GetBits(zgfx, extra);
 							count += zgfx->bits;
 						}
+
+						if (count > sizeof(zgfx->OutputBuffer) - zgfx->OutputCount)
+							return FALSE;
 
 						zgfx_history_buffer_ring_read(zgfx, distance, &(zgfx->OutputBuffer[zgfx->OutputCount]), count);
 						zgfx_history_buffer_ring_write(zgfx, &(zgfx->OutputBuffer[zgfx->OutputCount]), count);
@@ -325,6 +342,10 @@
 						zgfx->cBitsRemaining -= zgfx->cBitsCurrent;
 						zgfx->cBitsCurrent = 0;
 						zgfx->BitsCurrent = 0;
+
+						if (count > sizeof(zgfx->OutputBuffer) - zgfx->OutputCount)
+							return FALSE;
+
 						CopyMemory(&(zgfx->OutputBuffer[zgfx->OutputCount]), zgfx->pbInputCurrent, count);
 						zgfx_history_buffer_ring_write(zgfx, zgfx->pbInputCurrent, count);
 						zgfx->pbInputCurrent += count;
```
