# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1805_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1805_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 20-60 of the vulnerable file.

 * ANY SPECIAL, INCIDENTAL, INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND,
 * OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER OR NOT ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF 
 * LIABILITY, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE 
 * OF THIS SOFTWARE.
 */

#include "tiffiop.h"
#ifdef NEXT_SUPPORT
/*
 * TIFF Library.
 *
 * NeXT 2-bit Grey Scale Compression Algorithm Support
 */

#define SETPIXEL(op, v) {			\
	switch (npixels++ & 3) {		\
	case 0:	op[0]  = (unsigned char) ((v) << 6); break;	\
	case 1:	op[0] |= (v) << 4; break;	\
	case 2:	op[0] |= (v) << 2; break;	\
	case 3:	*op++ |= (v);	   break;	\
	}					\
}

#define LITERALROW	0x00
#define LITERALSPAN	0x40
#define WHITE   	((1<<2)-1)

static int
NeXTDecode(TIFF* tif, uint8* buf, tmsize_t occ, uint16 s)
{
	static const char module[] = "NeXTDecode";
	unsigned char *bp, *op;
	tmsize_t cc;
	uint8* row;
	tmsize_t scanline, n;

	(void) s;
	/*
	 * Each scanline is assumed to start off as all
	 * white (we assume a PhotometricInterpretation
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,7 +37,7 @@
 	case 0:	op[0]  = (unsigned char) ((v) << 6); break;	\
 	case 1:	op[0] |= (v) << 4; break;	\
 	case 2:	op[0] |= (v) << 2; break;	\
-	case 3:	*op++ |= (v);	   break;	\
+	case 3:	*op++ |= (v);	   op_offset++; break;	\
 	}					\
 }
 
@@ -106,6 +106,7 @@
 			uint32 imagewidth = tif->tif_dir.td_imagewidth;
             if( isTiled(tif) )
                 imagewidth = tif->tif_dir.td_tilewidth;
+            tmsize_t op_offset = 0;
 
 			/*
 			 * The scanline is composed of a sequence of constant
@@ -122,10 +123,15 @@
 				 * bounds, potentially resulting in a security
 				 * issue.
 				 */
-				while (n-- > 0 && npixels < imagewidth)
+				while (n-- > 0 && npixels < imagewidth && op_offset < scanline)
 					SETPIXEL(op, grey);
 				if (npixels >= imagewidth)
 					break;
+                if (op_offset >= scanline ) {
+                    TIFFErrorExt(tif->tif_clientdata, module, "Invalid data for scanline %ld",
+                        (long) tif->tif_row);
+                    return (0);
+                }
 				if (cc == 0)
 					goto bad;
 				n = *bp++, cc--;
```
