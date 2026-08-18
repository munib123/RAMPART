# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4788_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4788_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 121-161 of the vulnerable file.

  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickSignature);
  if (image_info->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",
      image_info->filename);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickSignature);
  image=AcquireImage(image_info);
  (void) ResetImagePage(image,"0x0+0+0");
  property=InterpretImageProperties(image_info,image,image_info->filename);
  (void) SetImageProperty(image,"label",property);
  property=DestroyString(property);
  label=GetImageProperty(image,"label");
  draw_info=CloneDrawInfo(image_info,(DrawInfo *) NULL);
  draw_info->text=ConstantString(label);
  metrics.width=0;
  metrics.ascent=0.0;
  status=GetMultilineTypeMetrics(image,draw_info,&metrics);
  if ((image->columns == 0) && (image->rows == 0))
    {
      image->columns=(size_t) (metrics.width+draw_info->stroke_width+0.5);
      image->rows=(size_t) floor(metrics.height+draw_info->stroke_width+0.5);
    }
  else
    if (((image->columns == 0) || (image->rows == 0)) ||
        (fabs(image_info->pointsize) < MagickEpsilon))
      {
        double
          high,
          low;

        /*
          Auto fit text into bounding box.
        */
        for ( ; ; draw_info->pointsize*=2.0)
        {
          (void) FormatLocaleString(geometry,MaxTextExtent,"%+g%+g",
            -metrics.bounds.x1,metrics.ascent);
          if (draw_info->gravity == UndefinedGravity)
            (void) CloneString(&draw_info->geometry,geometry);
          (void) GetMultilineTypeMetrics(image,draw_info,&metrics);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -138,7 +138,7 @@
   status=GetMultilineTypeMetrics(image,draw_info,&metrics);
   if ((image->columns == 0) && (image->rows == 0))
     {
-      image->columns=(size_t) (metrics.width+draw_info->stroke_width+0.5);
+      image->columns=(size_t) floor(metrics.width+draw_info->stroke_width+0.5);
       image->rows=(size_t) floor(metrics.height+draw_info->stroke_width+0.5);
     }
   else
@@ -207,14 +207,16 @@
       return((Image *) NULL);
     }
   if (image->columns == 0)
-    image->columns=(size_t) (metrics.width+draw_info->stroke_width+0.5);
+    image->columns=(size_t) floor(metrics.width+draw_info->stroke_width+0.5);
   if (image->columns == 0)
-    image->columns=(size_t) (draw_info->pointsize+draw_info->stroke_width+0.5);
+    image->columns=(size_t) floor(draw_info->pointsize+draw_info->stroke_width+
+      0.5);
   if (image->rows == 0)
-    image->rows=(size_t) (metrics.ascent-metrics.descent+
+    image->rows=(size_t) floor(metrics.ascent-metrics.descent+
       draw_info->stroke_width+0.5);
   if (image->rows == 0)
-    image->rows=(size_t) (draw_info->pointsize+draw_info->stroke_width+0.5);
+    image->rows=(size_t) floor(draw_info->pointsize+draw_info->stroke_width+
+      0.5);
   status=SetImageExtent(image,image->columns,image->rows);
   if (status == MagickFalse)
     {
```
