# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5215_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5215_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1040-1080 of the vulnerable file.

    status;

  MagickOffsetType
    progress;

  register ssize_t
    i;

  ssize_t
    y;

  /*
    Allocate histogram and stretch map.
  */
  assert(image != (Image *) NULL);
  assert(image->signature == MagickCoreSignature);
  if (image->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
  if (SetImageGray(image,exception) != MagickFalse)
    (void) SetImageColorspace(image,GRAYColorspace,exception);
  black=(double *) AcquireQuantumMemory(GetPixelChannels(image),sizeof(*black));
  white=(double *) AcquireQuantumMemory(GetPixelChannels(image),sizeof(*white));
  histogram=(double *) AcquireQuantumMemory(MaxMap+1UL,GetPixelChannels(image)*
    sizeof(*histogram));
  stretch_map=(double *) AcquireQuantumMemory(MaxMap+1UL,
    GetPixelChannels(image)*sizeof(*stretch_map));
  if ((black == (double *) NULL) || (white == (double *) NULL) ||
      (histogram == (double *) NULL) || (stretch_map == (double *) NULL))
    {
      if (stretch_map != (double *) NULL)
        stretch_map=(double *) RelinquishMagickMemory(stretch_map);
      if (histogram != (double *) NULL)
        histogram=(double *) RelinquishMagickMemory(histogram);
      if (white != (double *) NULL)
        white=(double *) RelinquishMagickMemory(white);
      if (black != (double *) NULL)
        black=(double *) RelinquishMagickMemory(black);
      ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
        image->filename);
    }
  /*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1057,6 +1057,8 @@
     (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
   if (SetImageGray(image,exception) != MagickFalse)
     (void) SetImageColorspace(image,GRAYColorspace,exception);
+  if (SyncImagePixelCache(image,exception) == MagickFalse)
+    return(MagickFalse);
   black=(double *) AcquireQuantumMemory(GetPixelChannels(image),sizeof(*black));
   white=(double *) AcquireQuantumMemory(GetPixelChannels(image),sizeof(*white));
   histogram=(double *) AcquireQuantumMemory(MaxMap+1UL,GetPixelChannels(image)*
@@ -1543,6 +1545,8 @@
 #endif
   if (image->debug != MagickFalse)
     (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
+  if (SyncImagePixelCache(image,exception) == MagickFalse)
+    return(MagickFalse);
   equalize_map=(double *) AcquireQuantumMemory(MaxMap+1UL,
     GetPixelChannels(image)*sizeof(*equalize_map));
   histogram=(double *) AcquireQuantumMemory(MaxMap+1UL,GetPixelChannels(image)*
```
