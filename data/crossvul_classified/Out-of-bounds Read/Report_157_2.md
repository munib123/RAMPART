# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 157_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `157_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 144-184 of the vulnerable file.

  while (pixelCount--) { // writing individual bits
    if (gfx->data.bpp&7/*not a multiple of one byte*/) {
      idx = idx & 7;
      if (shortCut && idx==0) {
        // Basically, if we're aligned and we're filling all 0 or all 1
        // then we can go really quickly and can just fill
        int wholeBytes = (gfx->data.bpp*(pixelCount+1)) >> 3;
        if (wholeBytes) {
          char c = (char)(col?0xFF:0);
          pixelCount = (short)(pixelCount+1 - (wholeBytes*8/gfx->data.bpp));
          while (wholeBytes--) {
            *ptr = c;
            ptr++;
          }
          continue;
        }
      }
      unsigned int mask = (unsigned int)(1<<gfx->data.bpp)-1;
      unsigned int existing = (unsigned int)*ptr;
      unsigned int bitIdx = (gfx->data.flags & JSGRAPHICSFLAGS_ARRAYBUFFER_MSB) ? 8-(idx+gfx->data.bpp) : idx;
      *ptr = (char)((existing&~(mask<<bitIdx)) | ((col&mask)<<bitIdx));
      if (gfx->data.flags & JSGRAPHICSFLAGS_ARRAYBUFFER_VERTICAL_BYTE) {
        ptr++;
      } else {
        idx += gfx->data.bpp;
        if (idx>=8) ptr++;
      }
    } else { // we're writing whole bytes
      int i;
      for (i=0;i<gfx->data.bpp;i+=8) {
        *ptr = (char)(col >> i);
        ptr++;
      }
    }
  }
}

// Faster implementation for where we have a flat memory area
void lcdSetPixel_ArrayBuffer_flat(JsGraphics *gfx, short x, short y, unsigned int col) {
  lcdSetPixels_ArrayBuffer_flat(gfx, x, y, 1, col);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -161,6 +161,7 @@
       unsigned int mask = (unsigned int)(1<<gfx->data.bpp)-1;
       unsigned int existing = (unsigned int)*ptr;
       unsigned int bitIdx = (gfx->data.flags & JSGRAPHICSFLAGS_ARRAYBUFFER_MSB) ? 8-(idx+gfx->data.bpp) : idx;
+      assert(ptr>=gfx->backendData && ptr<((char*)gfx->backendData + graphicsGetMemoryRequired(gfx)));
       *ptr = (char)((existing&~(mask<<bitIdx)) | ((col&mask)<<bitIdx));
       if (gfx->data.flags & JSGRAPHICSFLAGS_ARRAYBUFFER_VERTICAL_BYTE) {
         ptr++;
```
