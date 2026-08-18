# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 4813_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4813_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 528-568 of the vulnerable file.

    y;

  unsigned char
    *pixels;

   /*
    Open output image file.
  */
  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickSignature);
  assert(image != (Image *) NULL);
  assert(image->signature == MagickSignature);
  if (image->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
  status=OpenBlob(image_info,image,WriteBinaryBlobMode,&image->exception);
  if (status == MagickFalse)
    return(status);
  scene=0;

  quantum_info=AcquireQuantumInfo(image_info, image);
  if ((quantum_info->format == UndefinedQuantumFormat) &&
      (IsHighDynamicRangeImage(image,&image->exception) != MagickFalse))
    SetQuantumFormat(image,quantum_info,FloatingPointQuantumFormat);
  switch(quantum_info->depth){
  case 8:
    ipl_info.byteType = 0;
    break;
  case 16:
    if(quantum_info->format == SignedQuantumFormat){
      ipl_info.byteType = 2;
    }
    else{
      ipl_info.byteType = 1;
    }
    break;
  case 32:
    if(quantum_info->format == FloatingPointQuantumFormat){
      ipl_info.byteType = 3;
    }
    else{
      ipl_info.byteType = 4;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -545,6 +545,8 @@
   scene=0;
 
   quantum_info=AcquireQuantumInfo(image_info, image);
+  if (quantum_info == (QuantumInfo *) NULL)
+    ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
   if ((quantum_info->format == UndefinedQuantumFormat) &&
       (IsHighDynamicRangeImage(image,&image->exception) != MagickFalse))
     SetQuantumFormat(image,quantum_info,FloatingPointQuantumFormat);
```
