# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 5311_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5311_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 295-335 of the vulnerable file.

%
%  The format of the GetQuantumExtent method is:
%
%      size_t GetQuantumExtent(Image *image,const QuantumInfo *quantum_info,
%        const QuantumType quantum_type)
%
%  A description of each parameter follows:
%
%    o image: the image.
%
%    o quantum_info: the quantum info.
%
%    o quantum_type: Declare which pixel components to transfer (red, green,
%      blue, opacity, RGB, or RGBA).
%
*/
MagickExport size_t GetQuantumExtent(const Image *image,
  const QuantumInfo *quantum_info,const QuantumType quantum_type)
{
  size_t
    packet_size;

  assert(quantum_info != (QuantumInfo *) NULL);
  assert(quantum_info->signature == MagickCoreSignature);
  packet_size=1;
  switch (quantum_type)
  {
    case GrayAlphaQuantum: packet_size=2; break;
    case IndexAlphaQuantum: packet_size=2; break;
    case RGBQuantum: packet_size=3; break;
    case BGRQuantum: packet_size=3; break;
    case RGBAQuantum: packet_size=4; break;
    case RGBOQuantum: packet_size=4; break;
    case BGRAQuantum: packet_size=4; break;
    case CMYKQuantum: packet_size=4; break;
    case CMYKAQuantum: packet_size=5; break;
    default: break;
  }
  if (quantum_info->pack == MagickFalse)
    return((size_t) (packet_size*image->columns*((quantum_info->depth+7)/8)));
  return((size_t) ((packet_size*image->columns*quantum_info->depth+7)/8));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -312,6 +312,7 @@
   const QuantumInfo *quantum_info,const QuantumType quantum_type)
 {
   size_t
+    extent,
     packet_size;
 
   assert(quantum_info != (QuantumInfo *) NULL);
@@ -330,9 +331,10 @@
     case CMYKAQuantum: packet_size=5; break;
     default: break;
   }
+  extent=MagickMax(image->columns,image->rows);
   if (quantum_info->pack == MagickFalse)
-    return((size_t) (packet_size*image->columns*((quantum_info->depth+7)/8)));
-  return((size_t) ((packet_size*image->columns*quantum_info->depth+7)/8));
+    return((size_t) (packet_size*extent*((quantum_info->depth+7)/8)));
+  return((size_t) ((packet_size*extent*quantum_info->depth+7)/8));
 }
 
 
@@ -699,8 +701,9 @@
   if (quantum_info->pixels != (unsigned char **) NULL)
     DestroyQuantumPixels(quantum_info);
   quantum=(quantum_info->pad+6)*(quantum_info->depth+7)/8;
-  extent=image->columns*quantum;
-  if ((image->columns != 0) && (quantum != (extent/image->columns)))
+  extent=MagickMax(image->columns,image->rows)*quantum;
+  if ((MagickMax(image->columns,image->rows) != 0) &&
+      (quantum != (extent/MagickMax(image->columns,image->rows))))
     return(MagickFalse);
   return(AcquireQuantumPixels(quantum_info,extent));
 }
```
