# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 929_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `929_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 135-175 of the vulnerable file.


typedef struct _PixelChannels
{
  double
    channel[CompositePixelChannel];
} PixelChannels;

static PixelChannels **DestroyPixelThreadSet(PixelChannels **pixels)
{
  register ssize_t
    i;

  assert(pixels != (PixelChannels **) NULL);
  for (i=0; i < (ssize_t) GetMagickResourceLimit(ThreadResource); i++)
    if (pixels[i] != (PixelChannels *) NULL)
      pixels[i]=(PixelChannels *) RelinquishMagickMemory(pixels[i]);
  pixels=(PixelChannels **) RelinquishMagickMemory(pixels);
  return(pixels);
}

static PixelChannels **AcquirePixelThreadSet(const Image *image)
{
  PixelChannels
    **pixels;

  register ssize_t
    i;

  size_t
    number_threads;

  number_threads=(size_t) GetMagickResourceLimit(ThreadResource);
  pixels=(PixelChannels **) AcquireQuantumMemory(number_threads,
    sizeof(*pixels));
  if (pixels == (PixelChannels **) NULL)
    return((PixelChannels **) NULL);
  (void) memset(pixels,0,number_threads*sizeof(*pixels));
  for (i=0; i < (ssize_t) number_threads; i++)
  {
    register ssize_t
      j;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -152,8 +152,11 @@
   return(pixels);
 }
 
-static PixelChannels **AcquirePixelThreadSet(const Image *image)
-{
+static PixelChannels **AcquirePixelThreadSet(const Image *images)
+{
+  const Image
+    *next;
+
   PixelChannels
     **pixels;
 
@@ -161,6 +164,7 @@
     i;
 
   size_t
+    columns,
     number_threads;
 
   number_threads=(size_t) GetMagickResourceLimit(ThreadResource);
@@ -169,16 +173,18 @@
   if (pixels == (PixelChannels **) NULL)
     return((PixelChannels **) NULL);
   (void) memset(pixels,0,number_threads*sizeof(*pixels));
+  columns=images->columns;
+  for (next=images; next != (Image *) NULL; next=next->next)
+    columns=MagickMax(next->columns,columns);
   for (i=0; i < (ssize_t) number_threads; i++)
   {
     register ssize_t
       j;
 
-    pixels[i]=(PixelChannels *) AcquireQuantumMemory(image->columns,
-      sizeof(**pixels));
+    pixels[i]=(PixelChannels *) AcquireQuantumMemory(columns,sizeof(**pixels));
     if (pixels[i] == (PixelChannels *) NULL)
       return(DestroyPixelThreadSet(pixels));
-    for (j=0; j < (ssize_t) image->columns; j++)
+    for (j=0; j < (ssize_t) columns; j++)
     {
       register ssize_t
         k;
```
