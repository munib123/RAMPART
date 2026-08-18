# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 3123_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3123_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 84-124 of the vulnerable file.


ModifiablePixelBuffer::ModifiablePixelBuffer(const PixelFormat& pf,
                                             int w, int h)
  : PixelBuffer(pf, w, h)
{
}

ModifiablePixelBuffer::ModifiablePixelBuffer()
{
}

ModifiablePixelBuffer::~ModifiablePixelBuffer()
{
}

void ModifiablePixelBuffer::fillRect(const Rect& r, const void* pix)
{
  int stride;
  U8 *buf;
  int w, h, b;

  w = r.width();
  h = r.height();
  b = format.bpp/8;

  if (h == 0)
    return;

  buf = getBufferRW(r, &stride);

  if (b == 1) {
    while (h--) {
      memset(buf, *(const U8*)pix, w);
      buf += stride * b;
    }
  } else {
    U8 *start;
    int w1;

    start = buf;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,15 +101,26 @@
   int stride;
   U8 *buf;
   int w, h, b;
-
-  w = r.width();
-  h = r.height();
+  Rect drect;
+
+  drect = r;
+  if (!drect.enclosed_by(getRect())) {
+    vlog.error("Destination rect %dx%d at %d,%d exceeds framebuffer %dx%d",
+               drect.width(), drect.height(), drect.tl.x, drect.tl.y, width_, height_);
+    drect = drect.intersect(getRect());
+  }
+
+  if (drect.is_empty())
+    return;
+
+  w = drect.width();
+  h = drect.height();
   b = format.bpp/8;
 
   if (h == 0)
     return;
 
-  buf = getBufferRW(r, &stride);
+  buf = getBufferRW(drect, &stride);
 
   if (b == 1) {
     while (h--) {
@@ -136,7 +147,7 @@
     }
   }
 
-  commitBufferRW(r);
+  commitBufferRW(drect);
 }
 
 void ModifiablePixelBuffer::imageRect(const Rect& r,
```
