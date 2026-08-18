# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 951_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `951_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 1580-1621 of the vulnerable file.

%  RemoveDuplicateLayers() removes any image that is exactly the same as the
%  next image in the given image list.  Image size and virtual canvas offset
%  must also match, though not the virtual canvas size itself.
%
%  No check is made with regards to image disposal setting, though it is the
%  dispose setting of later image that is kept.  Also any time delays are also
%  added together. As such coalesced image animations should still produce the
%  same result, though with duplicte frames merged into a single frame.
%
%  The format of the RemoveDuplicateLayers method is:
%
%      void RemoveDuplicateLayers(Image **image,ExceptionInfo *exception)
%
%  A description of each parameter follows:
%
%    o images: the image list
%
%    o exception: return any errors or warnings in this structure.
%
*/
MagickExport void RemoveDuplicateLayers(Image **images,
     ExceptionInfo *exception)
{
  register Image
    *curr,
    *next;

  RectangleInfo
    bounds;

  assert((*images) != (const Image *) NULL);
  assert((*images)->signature == MagickCoreSignature);
  if ((*images)->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",(*images)->filename);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickCoreSignature);

  curr=GetFirstImageInList(*images);
  for (; (next=GetNextImageInList(curr)) != (Image *) NULL; curr=next)
  {
    if ( curr->columns != next->columns || curr->rows != next->rows
         || curr->page.x != next->page.x || curr->page.y != next->page.y )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1597,45 +1597,47 @@
 %    o exception: return any errors or warnings in this structure.
 %
 */
-MagickExport void RemoveDuplicateLayers(Image **images,
-     ExceptionInfo *exception)
+MagickExport void RemoveDuplicateLayers(Image **images,ExceptionInfo *exception)
 {
-  register Image
-    *curr,
-    *next;
-
   RectangleInfo
     bounds;
+
+  register Image
+    *image,
+    *next;
 
   assert((*images) != (const Image *) NULL);
   assert((*images)->signature == MagickCoreSignature);
   if ((*images)->debug != MagickFalse)
-    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",(*images)->filename);
+    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",
+      (*images)->filename);
   assert(exception != (ExceptionInfo *) NULL);
   assert(exception->signature == MagickCoreSignature);
-
-  curr=GetFirstImageInList(*images);
-  for (; (next=GetNextImageInList(curr)) != (Image *) NULL; curr=next)
+  image=GetFirstImageInList(*images);
+  for ( ; (next=GetNextImageInList(image)) != (Image *) NULL; image=next)
   {
-    if ( curr->columns != next->columns || curr->rows != next->rows
-         || curr->page.x != next->page.x || curr->page.y != next->page.y )
+    if ((image->columns != next->columns) || (image->rows != next->rows) ||
+        (image->page.x != next->page.x) || (image->page.y != next->page.y))
       continue;
-    bounds=CompareImagesBounds(curr,next,CompareAnyLayer,exception);
-    if ( bounds.x < 0 ) {
-      /*
-        the two images are the same, merge time delays and delete one.
-      */
-      size_t time;
-      time = curr->delay*1000/curr->ticks_per_second;
-      time += next->delay*1000/next->ticks_per_second;
-      next->ticks_per_second = 100L;
-      next->delay = time*curr->ticks_per_second/1000;
-      next->iterations = curr->iterations;
-      *images = curr;
-      (void) DeleteImageFromList(images);
-    }
+    bounds=CompareImagesBounds(image,next,CompareAnyLayer,exception);
+    if (bounds.x < 0)
+      {
+        /*
+          Two images are the same, merge time delays and delete one.
+        */
+        size_t
+          time;
+
+        time=1000*image->delay*PerceptibleReciprocal(image->ticks_per_second);
+        time+=1000*next->delay*PerceptibleReciprocal(next->ticks_per_second);
+        next->ticks_per_second=100L;
+        next->delay=time*image->ticks_per_second/1000;
+        next->iterations=image->iterations;
+        *images=image;
+        (void) DeleteImageFromList(images);
+      }
   }
-  *images = GetFirstImageInList(*images);
+  *images=GetFirstImageInList(*images);
 }
 
 
```
