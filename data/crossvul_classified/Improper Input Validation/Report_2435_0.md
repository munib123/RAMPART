# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2435_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2435_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 710-750 of the vulnerable file.

  DDSLookup_5_4
};

/*
  Macros
*/
#define C565_r(x) (((x) & 0xF800) >> 11)
#define C565_g(x) (((x) & 0x07E0) >> 5)
#define C565_b(x)  ((x) & 0x001F)

#define C565_red(x)   ( (C565_r(x) << 3 | C565_r(x) >> 2))
#define C565_green(x) ( (C565_g(x) << 2 | C565_g(x) >> 4))
#define C565_blue(x)  ( (C565_b(x) << 3 | C565_b(x) >> 2))

#define DIV2(x)  ((x) > 1 ? ((x) >> 1) : 1)

#define FixRange(min, max, steps) \
if (min > max) \
  min = max; \
if (max - min < steps) \
  max = Min(min + steps, 255); \
if (max - min < steps) \
  min = Max(min - steps, 0)

#define Dot(left, right) (left.x*right.x) + (left.y*right.y) + (left.z*right.z)

#define VectorInit(vector, value) vector.x = vector.y = vector.z = vector.w \
  = value
#define VectorInit3(vector, value) vector.x = vector.y = vector.z = value

#define IsBitMask(mask, r, g, b, a) (mask.r_bitmask == r && mask.g_bitmask == \
  g && mask.b_bitmask == b && mask.alpha_bitmask == a)

/*
  Forward declarations
*/
static MagickBooleanType
  ConstructOrdering(const size_t, const DDSVector4 *, const DDSVector3,
    DDSVector4 *, DDSVector4 *, unsigned char *, size_t);

static MagickBooleanType
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -727,9 +727,9 @@
 if (min > max) \
   min = max; \
 if (max - min < steps) \
-  max = Min(min + steps, 255); \
+  max = MagickMin(min + steps, 255); \
 if (max - min < steps) \
-  min = Max(min - steps, 0)
+  min = MagickMax(min - steps, 0)
 
 #define Dot(left, right) (left.x*right.x) + (left.y*right.y) + (left.z*right.z)
 
@@ -744,90 +744,30 @@
   Forward declarations
 */
 static MagickBooleanType
-  ConstructOrdering(const size_t, const DDSVector4 *, const DDSVector3,
-    DDSVector4 *, DDSVector4 *, unsigned char *, size_t);
-
-static MagickBooleanType
-  ReadDDSInfo(Image *, DDSInfo *);
-
-static MagickBooleanType
-  ReadDXT1(Image *, DDSInfo *, ExceptionInfo *);
-
-static MagickBooleanType
-  ReadDXT3(Image *, DDSInfo *, ExceptionInfo *);
-
-static MagickBooleanType
-  ReadDXT5(Image *, DDSInfo *, ExceptionInfo *);
-
-static MagickBooleanType
-  ReadUncompressedRGB(Image *, DDSInfo *, ExceptionInfo *);
-
-static MagickBooleanType
-  ReadUncompressedRGBA(Image *, DDSInfo *, ExceptionInfo *);
+  ConstructOrdering(const size_t,const DDSVector4 *,const DDSVector3,
+    DDSVector4 *,DDSVector4 *,unsigned char *,size_t),
+  ReadDDSInfo(Image *,DDSInfo *),
+  ReadDXT1(Image *,DDSInfo *,ExceptionInfo *),
+  ReadDXT3(Image *,DDSInfo *,ExceptionInfo *),
+  ReadDXT5(Image *,DDSInfo *,ExceptionInfo *),
+  ReadUncompressedRGB(Image *,DDSInfo *,ExceptionInfo *),
+  ReadUncompressedRGBA(Image *,DDSInfo *,ExceptionInfo *),
+  SkipDXTMipmaps(Image *,DDSInfo *,int,ExceptionInfo *),
+  SkipRGBMipmaps(Image *,DDSInfo *,int,ExceptionInfo *),
+  WriteDDSImage(const ImageInfo *,Image *),
+  WriteMipmaps(Image *,const size_t,const size_t,const size_t,
+    const MagickBooleanType,const MagickBooleanType,ExceptionInfo *);
 
 static void
-  RemapIndices(const ssize_t *, const unsigned char *, unsigned char *);
-
-static void
-  SkipDXTMipmaps(Image *, DDSInfo *, int);
-
-static void
-  SkipRGBMipmaps(Image *, DDSInfo *, int);
-
-static
-  MagickBooleanType WriteDDSImage(const ImageInfo *, Image *);
-
-static void
-  WriteDDSInfo(Image *, const size_t, const size_t, const size_t);
-
-static void
-  WriteFourCC(Image *, const size_t, const MagickBooleanType,
-    const MagickBooleanType, ExceptionInfo *);
-
-static void
-  WriteImageData(Image *, const size_t, const size_t, const MagickBooleanType,
-    const MagickBooleanType, ExceptionInfo *);
-
-static void
-  WriteIndices(Image *, const DDSVector3, const DDSVector3, unsigned char *);
-
-static MagickBooleanType
-  WriteMipmaps(Image *, const size_t, const size_t, const size_t,
-    const MagickBooleanType, const MagickBooleanType, ExceptionInfo *);
-
-static void
-  WriteSingleColorFit(Image *, const DDSVector4 *, const ssize_t *);
-
-static void
-  WriteUncompressed(Image *, ExceptionInfo *);
-
-static inline size_t Max(size_t one, size_t two)
-{
-  if (one > two)
-    return one;
-  return two;
-}
-
-static inline float MaxF(float one, float two)
-{
-  if (one > two)
-    return one;
-  return two;
-}
-
-static inline size_t Min(size_t one, size_t two)
-{
-  if (one < two)
-    return one;
-  return two;
-}
-
-static inline float MinF(float one, float two)
-{
-  if (one < two)
-    return one;
-  return two;
-}
+  RemapIndices(const ssize_t *,const unsigned char *,unsigned char *),
+  WriteDDSInfo(Image *,const size_t,const size_t,const size_t),
+  WriteFourCC(Image *,const size_t,const MagickBooleanType,
+    const MagickBooleanType,ExceptionInfo *),
+  WriteImageData(Image *,const size_t,const size_t,const MagickBooleanType,
+    const MagickBooleanType,ExceptionInfo *),
+  WriteIndices(Image *,const DDSVector3,const DDSVector3, unsigned char *),
+  WriteSingleColorFit(Image *,const DDSVector4 *,const ssize_t *),
+  WriteUncompressed(Image *,ExceptionInfo *);
 
 static inline void VectorAdd(const DDSVector4 left, const DDSVector4 right,
   DDSVector4 *destination)
@@ -840,17 +780,17 @@
 
 static inline void VectorClamp(DDSVector4 *value)
 {
-  value->x = MinF(1.0f,MaxF(0.0f,value->x));
-  value->y = MinF(1.0f,MaxF(0.0f,value->y));
-  value->z = MinF(1.0f,MaxF(0.0f,value->z));
-  value->w = MinF(1.0f,MaxF(0.0f,value->w));
+  value->x = MagickMin(1.0f,MagickMax(0.0f,value->x));
+  value->y = MagickMin(1.0f,MagickMax(0.0f,value->y));
+  value->z = MagickMin(1.0f,MagickMax(0.0f,value->z));
+  value->w = MagickMin(1.0f,MagickMax(0.0f,value->w));
 }
 
 static inline void VectorClamp3(DDSVector3 *value)
 {
-  value->x = MinF(1.0f,MaxF(0.0f,value->x));
-  value->y = MinF(1.0f,MaxF(0.0f,value->y));
-  value->z = MinF(1.0f,MaxF(0.0f,value->z));
+  value->x = MagickMin(1.0f,MagickMax(0.0f,value->x));
+  value->y = MagickMin(1.0f,MagickMax(0.0f,value->y));
+  value->z = MagickMin(1.0f,MagickMax(0.0f,value->z));
 }
 
 static inline void VectorCopy43(const DDSVector4 source,
@@ -1475,7 +1415,7 @@
     w.z = (row2.z * v.z) + w.z;
     w.w = (row2.w * v.z) + w.w;
 
-    a = 1.0f / MaxF(w.x,MaxF(w.y,w.z));
+    a = 1.0f / MagickMax(w.x,MagickMax(w.y,w.z));
 
     v.x = w.x * a;
     v.y = w.y * a;
@@ -1962,8 +1902,8 @@
     for (x = 0; x < (ssize_t) dds_info->width; x += 4)
     {
       /* Get 4x4 patch of pixels to write on */
-      q = QueueAuthenticPixels(image, x, y, Min(4, dds_info->width - x),
-        Min(4, dds_info->height - y),exception);
+      q = QueueAuthenticPixels(image, x, y, MagickMin(4, dds_info->width - x),
+        MagickMin(4, dds_info->height - y),exception);
 
       if (q == (PixelPacket *) NULL)
         return MagickFalse;
@@ -2000,9 +1940,7 @@
     }
   }
 
-  SkipDXTMipmaps(image, dds_info, 8);
-
-  return MagickTrue;
+  return(SkipDXTMipmaps(image,dds_info,8,exception));
 }
 
 static MagickBooleanType ReadDXT3(Image *image, DDSInfo *dds_info,
@@ -2040,8 +1978,8 @@
     for (x = 0; x < (ssize_t) dds_info->width; x += 4)
     {
       /* Get 4x4 patch of pixels to write on */
-      q = QueueAuthenticPixels(image, x, y, Min(4, dds_info->width - x),
-                         Min(4, dds_info->height - y),exception);
+      q = QueueAuthenticPixels(image, x, y, MagickMin(4, dds_info->width - x),
+                         MagickMin(4, dds_info->height - y),exception);
 
       if (q == (PixelPacket *) NULL)
         return MagickFalse;
@@ -2087,9 +2025,7 @@
     }
   }
 
-  SkipDXTMipmaps(image, dds_info, 16);
-
-  return MagickTrue;
+  return(SkipDXTMipmaps(image,dds_info,16,exception));
 }
 
 static MagickBooleanType ReadDXT5(Image *image, DDSInfo *dds_info,
@@ -2131,8 +2067,8 @@
     for (x = 0; x < (ssize_t) dds_info->width; x += 4)
     {
       /* Get 4x4 patch of pixels to write on */
-      q = QueueAuthenticPixels(image, x, y, Min(4, dds_info->width - x),
-                         Min(4, dds_info->height - y),exception);
+      q = QueueAuthenticPixels(image, x, y, MagickMin(4, dds_info->width - x),
+                         MagickMin(4, dds_info->height - y),exception);
 
       if (q == (PixelPacket *) NULL)
         return MagickFalse;
@@ -2188,9 +2124,7 @@
     }
   }
 
-  SkipDXTMipmaps(image, dds_info, 16);
-
-  return MagickTrue;
+  return(SkipDXTMipmaps(image,dds_info,16,exception));
 }
 
 static MagickBooleanType ReadUncompressedRGB(Image *image, DDSInfo *dds_info,
@@ -2252,9 +2186,7 @@
       return MagickFalse;
   }
 
-  SkipRGBMipmaps(image, dds_info, 3);
-
-  return MagickTrue;
+  return(SkipRGBMipmaps(image,dds_info,3,exception));
 }
 
 static MagickBooleanType ReadUncompressedRGBA(Image *image, DDSInfo *dds_info,
@@ -2346,9 +2278,7 @@
       return MagickFalse;
   }
 
-  SkipRGBMipmaps(image, dds_info, 4);
-
-  return MagickTrue;
+  return(SkipRGBMipmaps(image,dds_info,4,exception));
 }
 
 
@@ -2425,7 +2355,8 @@
 /*
   Skip the mipmap images for compressed (DXTn) dds files
 */
-static void SkipDXTMipmaps(Image *image, DDSInfo *dds_info, int texel_size)
+static MagickBooleanType SkipDXTMipmaps(Image *image,DDSInfo *dds_info,
+  int texel_size,ExceptionInfo *exception)
 {
   register ssize_t
     i;
@@ -2444,6 +2375,12 @@
... (diff truncated)
```
