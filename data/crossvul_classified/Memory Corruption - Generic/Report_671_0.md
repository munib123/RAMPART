# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 671_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `671_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 15-73 of the vulnerable file.

 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_CODEC_ZGFX_H
#define FREERDP_CODEC_ZGFX_H

#include <freerdp/api.h>
#include <freerdp/types.h>

#include <freerdp/codec/bulk.h>

#define ZGFX_SEGMENTED_SINGLE			0xE0
#define ZGFX_SEGMENTED_MULTIPART		0xE1

#define ZGFX_PACKET_COMPR_TYPE_RDP8		0x04

#define ZGFX_SEGMENTED_MAXSIZE			65535

struct _ZGFX_CONTEXT
{
	BOOL Compressor;

	const BYTE* pbInputCurrent;
	const BYTE* pbInputEnd;

	UINT32 bits;
	UINT32 cBitsRemaining;
	UINT32 BitsCurrent;
	UINT32 cBitsCurrent;

	BYTE OutputBuffer[65536];
	UINT32 OutputCount;

	BYTE HistoryBuffer[2500000];
	UINT32 HistoryIndex;
	UINT32 HistoryBufferSize;
};
typedef struct _ZGFX_CONTEXT ZGFX_CONTEXT;

#ifdef __cplusplus
extern "C" {
#endif

FREERDP_API int zgfx_decompress(ZGFX_CONTEXT* zgfx, const BYTE* pSrcData, UINT32 SrcSize, BYTE** ppDstData, UINT32* pDstSize, UINT32 flags);
FREERDP_API int zgfx_compress(ZGFX_CONTEXT* zgfx, const BYTE* pSrcData, UINT32 SrcSize, BYTE** ppDstData, UINT32* pDstSize, UINT32* pFlags);
FREERDP_API int zgfx_compress_to_stream(ZGFX_CONTEXT* zgfx, wStream* sDst, const BYTE* pUncompressed, UINT32 uncompressedSize, UINT32* pFlags);

FREERDP_API void zgfx_context_reset(ZGFX_CONTEXT* zgfx, BOOL flush);

FREERDP_API ZGFX_CONTEXT* zgfx_context_new(BOOL Compressor);
FREERDP_API void zgfx_context_free(ZGFX_CONTEXT* zgfx);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_CODEC_ZGFX_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,34 +32,18 @@
 
 #define ZGFX_SEGMENTED_MAXSIZE			65535
 
-struct _ZGFX_CONTEXT
-{
-	BOOL Compressor;
-
-	const BYTE* pbInputCurrent;
-	const BYTE* pbInputEnd;
-
-	UINT32 bits;
-	UINT32 cBitsRemaining;
-	UINT32 BitsCurrent;
-	UINT32 cBitsCurrent;
-
-	BYTE OutputBuffer[65536];
-	UINT32 OutputCount;
-
-	BYTE HistoryBuffer[2500000];
-	UINT32 HistoryIndex;
-	UINT32 HistoryBufferSize;
-};
 typedef struct _ZGFX_CONTEXT ZGFX_CONTEXT;
 
 #ifdef __cplusplus
 extern "C" {
 #endif
 
-FREERDP_API int zgfx_decompress(ZGFX_CONTEXT* zgfx, const BYTE* pSrcData, UINT32 SrcSize, BYTE** ppDstData, UINT32* pDstSize, UINT32 flags);
-FREERDP_API int zgfx_compress(ZGFX_CONTEXT* zgfx, const BYTE* pSrcData, UINT32 SrcSize, BYTE** ppDstData, UINT32* pDstSize, UINT32* pFlags);
-FREERDP_API int zgfx_compress_to_stream(ZGFX_CONTEXT* zgfx, wStream* sDst, const BYTE* pUncompressed, UINT32 uncompressedSize, UINT32* pFlags);
+FREERDP_API int zgfx_decompress(ZGFX_CONTEXT* zgfx, const BYTE* pSrcData, UINT32 SrcSize,
+                                BYTE** ppDstData, UINT32* pDstSize, UINT32 flags);
+FREERDP_API int zgfx_compress(ZGFX_CONTEXT* zgfx, const BYTE* pSrcData, UINT32 SrcSize,
+                              BYTE** ppDstData, UINT32* pDstSize, UINT32* pFlags);
+FREERDP_API int zgfx_compress_to_stream(ZGFX_CONTEXT* zgfx, wStream* sDst,
+                                        const BYTE* pUncompressed, UINT32 uncompressedSize, UINT32* pFlags);
 
 FREERDP_API void zgfx_context_reset(ZGFX_CONTEXT* zgfx, BOOL flush);
 
@@ -71,4 +55,4 @@
 #endif
 
 #endif /* FREERDP_CODEC_ZGFX_H */
- 
+
```
