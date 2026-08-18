# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5294_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5294_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 752-792 of the vulnerable file.

  return(OverCompositeOp);
}

static inline void ReversePSDString(Image *image,char *p,size_t length)
{
  char
    *q;

  if (image->endian == MSBEndian)
    return;

  q=p+length;
  for(--q; p < q; ++p, --q)
  {
    *p = *p ^ *q,
    *q = *p ^ *q,
    *p = *p ^ *q;
  }
}

static MagickBooleanType ReadPSDChannelPixels(Image *image,
  const size_t channels,const size_t row,const ssize_t type,
  const unsigned char *pixels,ExceptionInfo *exception)
{
  Quantum
    pixel;

  register const unsigned char
    *p;

  register Quantum
    *q;

  register ssize_t
    x;

  size_t
    packet_size;

  unsigned short
    nibble;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -769,6 +769,72 @@
   }
 }
 
+static inline void SetPSDPixel(Image *image,const size_t channels,
+  const ssize_t type,const size_t packet_size,const Quantum pixel,Quantum *q,
+  ExceptionInfo *exception)
+{
+  if (image->storage_class == PseudoClass)
+    {
+      if (packet_size == 1)
+        SetPixelIndex(image,ScaleQuantumToChar(pixel),q);
+      else
+        SetPixelIndex(image,ScaleQuantumToShort(pixel),q);
+      SetPixelViaPixelInfo(image,image->colormap+(ssize_t)
+        ConstrainColormapIndex(image,GetPixelIndex(image,q),exception),q);
+      return;
+    }
+  switch (type)
+  {
+    case -1:
+    {
+      SetPixelAlpha(image, pixel,q);
+      break;
+    }
+    case -2:
+    case 0:
+    {
+      SetPixelRed(image,pixel,q);
+      if (channels == 1 || type == -2)
+        SetPixelGray(image,pixel,q);
+      break;
+    }
+    case 1:
+    {
+      if (image->storage_class == PseudoClass)
+        SetPixelAlpha(image,pixel,q);
+      else
+        SetPixelGreen(image,pixel,q);
+      break;
+    }
+    case 2:
+    {
+      if (image->storage_class == PseudoClass)
+        SetPixelAlpha(image,pixel,q);
+      else
+        SetPixelBlue(image,pixel,q);
+      break;
+    }
+    case 3:
+    {
+      if (image->colorspace == CMYKColorspace)
+        SetPixelBlack(image,pixel,q);
+      else
+        if (image->alpha_trait != UndefinedPixelTrait)
+          SetPixelAlpha(image,pixel,q);
+      break;
+    }
+    case 4:
+    {
+      if ((IssRGBCompatibleColorspace(image->colorspace) != MagickFalse) &&
+          (channels > 3))
+        break;
+      if (image->alpha_trait != UndefinedPixelTrait)
+        SetPixelAlpha(image,pixel,q);
+      break;
+    }
+  }
+}
+
 static MagickBooleanType ReadPSDChannelPixels(Image *image,
   const size_t channels,const size_t row,const ssize_t type,
   const unsigned char *pixels,ExceptionInfo *exception)
@@ -805,90 +871,31 @@
         p=PushShortPixel(MSBEndian,p,&nibble);
         pixel=ScaleShortToQuantum(nibble);
       }
-    switch (type)
-    {
-      case -1:
+    if (image->depth > 1)
       {
-        SetPixelAlpha(image,pixel,q);
-        break;
+        SetPSDPixel(image,channels,type,packet_size,pixel,q,exception);
+        q+=GetPixelChannels(image);
       }
-      case -2:
-      case 0:
+    else
       {
-        SetPixelRed(image,pixel,q);
-        if (channels == 1 || type == -2)
-          SetPixelGray(image,pixel,q);
-        if (image->storage_class == PseudoClass)
-          {
-            if (packet_size == 1)
-              SetPixelIndex(image,ScaleQuantumToChar(pixel),q);
-            else
-              SetPixelIndex(image,ScaleQuantumToShort(pixel),q);
-            SetPixelViaPixelInfo(image,image->colormap+(ssize_t)
-              ConstrainColormapIndex(image,GetPixelIndex(image,q),exception),q);
-            if (image->depth == 1)
-              {
-                ssize_t
-                  bit,
-                  number_bits;
-  
-                number_bits=image->columns-x;
-                if (number_bits > 8)
-                  number_bits=8;
-                for (bit=0; bit < number_bits; bit++)
-                {
-                  SetPixelIndex(image,(((unsigned char) pixel) &
-                    (0x01 << (7-bit))) != 0 ? 0 : 255,q);
-                  SetPixelViaPixelInfo(image,image->colormap+(ssize_t)
-                    ConstrainColormapIndex(image,GetPixelIndex(image,q),
-                      exception),q);
-                  q+=GetPixelChannels(image);
-                  x++;
-                }
-                x--;
-                continue;
-              }
-          }
-        break;
+        ssize_t
+          bit,
+          number_bits;
+      
+        number_bits=image->columns-x;
+        if (number_bits > 8)
+          number_bits=8;
+        for (bit = 0; bit < number_bits; bit++)
+        {
+          SetPSDPixel(image,channels,type,packet_size,(((unsigned char) pixel)
+            & (0x01 << (7-bit))) != 0 ? 0 : 255,q,exception);
+          q+=GetPixelChannels(image);
+          x++;
+        }
+        if (x != image->columns)
+          x--;
+        continue;
       }
-      case 1:
-      {
-        if (image->storage_class == PseudoClass)
-          SetPixelAlpha(image,pixel,q);
-        else
-          SetPixelGreen(image,pixel,q);
-        break;
-      }
-      case 2:
-      {
-        if (image->storage_class == PseudoClass)
-          SetPixelAlpha(image,pixel,q);
-        else
-          SetPixelBlue(image,pixel,q);
-        break;
-      }
-      case 3:
-      {
-        if (image->colorspace == CMYKColorspace)
-          SetPixelBlack(image,pixel,q);
-        else
-          if (image->alpha_trait != UndefinedPixelTrait)
-            SetPixelAlpha(image,pixel,q);
-        break;
-      }
-      case 4:
-      {
-        if ((IssRGBCompatibleColorspace(image->colorspace) != MagickFalse) &&
-            (channels > 3))
-          break;
-        if (image->alpha_trait != UndefinedPixelTrait)
-          SetPixelAlpha(image,pixel,q);
-        break;
-      }
-      default:
-        break;
-    }
-    q+=GetPixelChannels(image);
   }
   return(SyncAuthenticPixels(image,exception));
 }
```
