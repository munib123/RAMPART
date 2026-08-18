# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5053_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5053_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1414-1454 of the vulnerable file.

  DrawInfo
    *clone_info;

  MagickStatusType
    status;

  assert(image != (Image *) NULL);
  assert(image->signature == MagickCoreSignature);
  if (image->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
  assert(draw_info != (const DrawInfo *) NULL);
  (void) FormatLocaleString(filename,MagickPathExtent,"%s",name);
  value=GetImageArtifact(image,filename);
  if (value == (const char *) NULL)
    return(MagickFalse);
  clip_mask=CloneImage(image,image->columns,image->rows,MagickTrue,exception);
  if (clip_mask == (Image *) NULL)
    return(MagickFalse);
  (void) QueryColorCompliance("#0000",AllCompliance,
    &clip_mask->background_color,exception);
  clip_mask->background_color.alpha=(Quantum) TransparentAlpha;
  (void) SetImageBackgroundColor(clip_mask,exception);
  if (image->debug != MagickFalse)
    (void) LogMagickEvent(DrawEvent,GetMagickModule(),"\nbegin clip-path %s",
      draw_info->clip_mask);
  clone_info=CloneDrawInfo((ImageInfo *) NULL,draw_info);
  (void) CloneString(&clone_info->primitive,value);
  (void) QueryColorCompliance("#ffffff",AllCompliance,&clone_info->fill,
    exception);
  clone_info->clip_mask=(char *) NULL;
  status=NegateImage(clip_mask,MagickFalse,exception);
  (void) SetImageMask(image,ReadPixelMask,clip_mask,exception);
  clip_mask=DestroyImage(clip_mask);
  status&=DrawImage(image,clone_info,exception);
  clone_info=DestroyDrawInfo(clone_info);
  if (image->debug != MagickFalse)
    (void) LogMagickEvent(DrawEvent,GetMagickModule(),"end clip-path");
  return(status != 0 ? MagickTrue : MagickFalse);
}


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1431,7 +1431,7 @@
     return(MagickFalse);
   (void) QueryColorCompliance("#0000",AllCompliance,
     &clip_mask->background_color,exception);
-  clip_mask->background_color.alpha=(Quantum) TransparentAlpha;
+  clip_mask->background_color.alpha=(MagickRealType) TransparentAlpha;
   (void) SetImageBackgroundColor(clip_mask,exception);
   if (image->debug != MagickFalse)
     (void) LogMagickEvent(DrawEvent,GetMagickModule(),"\nbegin clip-path %s",
@@ -1556,7 +1556,7 @@
   status=MagickTrue;
   maximum_length=0.0;
   total_length=0.0;
-  for (i=1; (i < number_vertices) && (length >= 0.0); i++)
+  for (i=1; (i < (ssize_t) number_vertices) && (length >= 0.0); i++)
   {
     dx=primitive_info[i].point.x-primitive_info[i-1].point.x;
     dy=primitive_info[i].point.y-primitive_info[i-1].point.y;
@@ -1810,7 +1810,7 @@
     /*
       Interpret graphic primitive.
     */
-    GetNextToken(q,&q,extent,keyword);
+    GetNextToken(q,&q,MagickPathExtent,keyword);
     if (*keyword == '\0')
       break;
     if (*keyword == '#')
@@ -2120,7 +2120,7 @@
             GetNextToken(q,&q,extent,token);
             weight=ParseCommandOption(MagickWeightOptions,MagickFalse,token);
             if (weight == -1)
-              weight=StringToUnsignedLong(token);
+              weight=(ssize_t) StringToUnsignedLong(token);
             graphic_context[n]->weight=(size_t) weight;
             break;
           }
@@ -2369,7 +2369,8 @@
                 (void) SetImageArtifact(image,key,token);
                 (void) FormatLocaleString(key,MagickPathExtent,"%s-type",name);
                 (void) SetImageArtifact(image,key,type);
-                (void) FormatLocaleString(key,MagickPathExtent,"%s-geometry",name);
+                (void) FormatLocaleString(key,MagickPathExtent,"%s-geometry",
+                  name);
                 (void) FormatLocaleString(geometry,MagickPathExtent,
                   "%gx%g%+.15g%+.15g",
                   MagickMax(fabs(bounds.x2-bounds.x1+1.0),1.0),
@@ -4628,7 +4629,7 @@
           */
           clone_info=CloneDrawInfo((ImageInfo *) NULL,draw_info);
           clone_info->stroke_width=0.0;
-          clone_info->stroke.alpha=(Quantum) TransparentAlpha;
+          clone_info->stroke.alpha=(MagickRealType) TransparentAlpha;
           status&=DrawPolygonPrimitive(image,clone_info,primitive_info,
             exception);
           clone_info=DestroyDrawInfo(clone_info);
@@ -4663,7 +4664,7 @@
             }
           clone_info=CloneDrawInfo((ImageInfo *) NULL,draw_info);
           clone_info->stroke_width=0.0;
-          clone_info->stroke.alpha=(Quantum) TransparentAlpha;
+          clone_info->stroke.alpha=(MagickRealType) TransparentAlpha;
           status&=DrawPolygonPrimitive(image,clone_info,primitive_info,
             exception);
           clone_info=DestroyDrawInfo(clone_info);
@@ -4764,7 +4765,7 @@
   if (clone_info->stroke_pattern != (Image *) NULL)
     clone_info->fill_pattern=CloneImage(clone_info->stroke_pattern,0,0,
       MagickTrue,exception);
-  clone_info->stroke.alpha=(Quantum) TransparentAlpha;
+  clone_info->stroke.alpha=(MagickRealType) TransparentAlpha;
   clone_info->stroke_width=0.0;
   clone_info->fill_rule=NonZeroRule;
   status=MagickTrue;
@@ -4881,7 +4882,7 @@
   draw_info->miterlimit=10;
   draw_info->decorate=NoDecoration;
   draw_info->pointsize=12.0;
-  draw_info->undercolor.alpha=(Quantum) TransparentAlpha;
+  draw_info->undercolor.alpha=(MagickRealType) TransparentAlpha;
   draw_info->compose=OverCompositeOp;
   draw_info->render=MagickTrue;
   draw_info->debug=IsEventLogging();
@@ -4948,7 +4949,7 @@
 
       weight=ParseCommandOption(MagickWeightOptions,MagickFalse,option);
       if (weight == -1)
-        weight=StringToUnsignedLong(option);
+        weight=(ssize_t) StringToUnsignedLong(option);
       draw_info->weight=(size_t) weight;
     }
   exception=DestroyExceptionInfo(exception);
@@ -6046,17 +6047,29 @@
       }
     if (q >= (ssize_t) (max_strokes-6*BezierQuantum-360))
       {
-         max_strokes+=6*BezierQuantum+360;
-         path_p=(PointInfo *) ResizeQuantumMemory(path_p,(size_t) max_strokes,
-           sizeof(*path_p));
-         path_q=(PointInfo *) ResizeQuantumMemory(path_q,(size_t) max_strokes,
-           sizeof(*path_q));
-         if ((path_p == (PointInfo *) NULL) || (path_q == (PointInfo *) NULL))
-           {
-             polygon_primitive=(PrimitiveInfo *)
-               RelinquishMagickMemory(polygon_primitive);
-             return((PrimitiveInfo *) NULL);
-           }
+        if (~max_strokes < (6*BezierQuantum+360))
+          {
+            path_p=(PointInfo *) RelinquishMagickMemory(path_p);
+            path_q=(PointInfo *) RelinquishMagickMemory(path_q);
+          }
+        else
+          {
+            max_strokes+=6*BezierQuantum+360;
+            path_p=(PointInfo *) ResizeQuantumMemory(path_p,max_strokes,
+              sizeof(*path_p));
+            path_q=(PointInfo *) ResizeQuantumMemory(path_q,max_strokes,
+              sizeof(*path_q));
+          }
+        if ((path_p == (PointInfo *) NULL) || (path_q == (PointInfo *) NULL))
+          {
+            if (path_p != (PointInfo *) NULL)
+              path_p=(PointInfo *) RelinquishMagickMemory(path_p);
+            if (path_q != (PointInfo *) NULL)
+              path_q=(PointInfo *) RelinquishMagickMemory(path_q);
+            polygon_primitive=(PrimitiveInfo *)
+              RelinquishMagickMemory(polygon_primitive);
+            return((PrimitiveInfo *) NULL);
+          }
       }
     dot_product=dx.q*dy.p-dx.p*dy.q;
     if (dot_product <= 0.0)
```
