# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 930_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `930_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 133-173 of the vulnerable file.

%
%    o value: A value value.
%
%    o exception: return any errors or warnings in this structure.
%
*/

static MagickPixelPacket **DestroyPixelThreadSet(MagickPixelPacket **pixels)
{
  register ssize_t
    i;

  assert(pixels != (MagickPixelPacket **) NULL);
  for (i=0; i < (ssize_t) GetMagickResourceLimit(ThreadResource); i++)
    if (pixels[i] != (MagickPixelPacket *) NULL)
      pixels[i]=(MagickPixelPacket *) RelinquishMagickMemory(pixels[i]);
  pixels=(MagickPixelPacket **) RelinquishMagickMemory(pixels);
  return(pixels);
}

static MagickPixelPacket **AcquirePixelThreadSet(const Image *image)
{
  MagickPixelPacket
    **pixels;

  register ssize_t
    i,
    j;

  size_t
    number_threads;

  number_threads=(size_t) GetMagickResourceLimit(ThreadResource);
  pixels=(MagickPixelPacket **) AcquireQuantumMemory(number_threads,
    sizeof(*pixels));
  if (pixels == (MagickPixelPacket **) NULL)
    return((MagickPixelPacket **) NULL);
  (void) memset(pixels,0,number_threads*sizeof(*pixels));
  for (i=0; i < (ssize_t) number_threads; i++)
  {
    pixels[i]=(MagickPixelPacket *) AcquireQuantumMemory(image->columns,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,8 +150,11 @@
   return(pixels);
 }
 
-static MagickPixelPacket **AcquirePixelThreadSet(const Image *image)
-{
+static MagickPixelPacket **AcquirePixelThreadSet(const Image *images)
+{
+  const Image
+    *next;
+
   MagickPixelPacket
     **pixels;
 
@@ -160,6 +163,7 @@
     j;
 
   size_t
+    columns,
     number_threads;
 
   number_threads=(size_t) GetMagickResourceLimit(ThreadResource);
@@ -168,14 +172,17 @@
   if (pixels == (MagickPixelPacket **) NULL)
     return((MagickPixelPacket **) NULL);
   (void) memset(pixels,0,number_threads*sizeof(*pixels));
+  columns=images->columns;
+  for (next=images; next != (Image *) NULL; next=next->next)
+    columns=MagickMax(next->columns,columns);
   for (i=0; i < (ssize_t) number_threads; i++)
   {
-    pixels[i]=(MagickPixelPacket *) AcquireQuantumMemory(image->columns,
+    pixels[i]=(MagickPixelPacket *) AcquireQuantumMemory(columns,
       sizeof(**pixels));
     if (pixels[i] == (MagickPixelPacket *) NULL)
       return(DestroyPixelThreadSet(pixels));
-    for (j=0; j < (ssize_t) image->columns; j++)
-      GetMagickPixelPacket(image,&pixels[i][j]);
+    for (j=0; j < (ssize_t) columns; j++)
+      GetMagickPixelPacket(images,&pixels[i][j]);
   }
   return(pixels);
 }
```
