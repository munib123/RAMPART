# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 1834_2
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1834_2`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 207-248 of the vulnerable file.

%                                                                             %
%                                                                             %
%   G e t M a g i c k F e a t u r e s                                         %
%                                                                             %
%                                                                             %
%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
%  GetMagickFeatures() returns the ImageMagick features.
%
%  The format of the GetMagickFeatures method is:
%
%      const char *GetMagickFeatures(void)
%
%  No parameters are required.
%
*/
MagickExport const char *GetMagickFeatures(void)
{
  return "DPC"
#if defined(MAGICKCORE_BUILD_MODULES) || defined(_DLL)
  " Modules"
#endif
#if defined(MAGICKCORE_HDRI_SUPPORT)
  " HDRI"
#endif
#if defined(MAGICKCORE_OPENCL_SUPPORT)
  " OpenCL"
#endif
#if defined(MAGICKCORE_OPENMP_SUPPORT)
  " OpenMP"
#endif
  ;
}


/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%                                                                             %
%                                                                             %
%                                                                             %
%   G e t M a g i c k H o m e U R L                                           %
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -224,17 +224,26 @@
 MagickExport const char *GetMagickFeatures(void)
 {
   return "DPC"
+#if defined(MAGICKCORE_WINDOWS_SUPPORT) && defined(_DEBUG)
+  " Debug"
+#endif
+#if defined(MAGICKCORE_CIPHER_SUPPORT)
+  " Cipher"
+#endif
+#if defined(MAGICKCORE_HDRI_SUPPORT)
+  " HDRI"
+#endif
 #if defined(MAGICKCORE_BUILD_MODULES) || defined(_DLL)
   " Modules"
 #endif
-#if defined(MAGICKCORE_HDRI_SUPPORT)
-  " HDRI"
-#endif
 #if defined(MAGICKCORE_OPENCL_SUPPORT)
   " OpenCL"
 #endif
 #if defined(MAGICKCORE_OPENMP_SUPPORT)
   " OpenMP"
+#endif
+#if defined(ZERO_CONFIGURATION_SUPPORT)
+  " Zero-configuration"
 #endif
   ;
 }
```
