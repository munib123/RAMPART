# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5316_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5316_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 408-448 of the vulnerable file.

  image->columns=(size_t) pdb_image.width;
  image->rows=(size_t) pdb_image.height;
  image->depth=8;
  image->storage_class=PseudoClass;
  bits_per_pixel=pdb_image.type == 0 ? 2UL : pdb_image.type == 2 ? 4UL : 1UL;
  one=1;
  if (AcquireImageColormap(image,one << bits_per_pixel) == MagickFalse)
    ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
  if (image_info->ping != MagickFalse)
    {
      (void) CloseBlob(image);
      return(GetFirstImageInList(image));
    }
  status=SetImageExtent(image,image->columns,image->rows);
  if (status == MagickFalse)
    {
      InheritException(exception,&image->exception);
      return(DestroyImageList(image));
    }
  packets=(bits_per_pixel*image->columns+7)/8;
  pixels=(unsigned char *) AcquireQuantumMemory(packets+256UL,image->rows*
    sizeof(*pixels));
  if (pixels == (unsigned char *) NULL)
    ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
  switch (pdb_image.version & 0x07)
  {
    case 0:
    {
      image->compression=NoCompression;
      count=(ssize_t) ReadBlob(image, packets * image -> rows, pixels);
      break;
    }
    case 1:
    {
      image->compression=RLECompression;
      if (!DecodeImage(image, pixels, packets * image -> rows))
        ThrowReaderException( CorruptImageError, "RLEDecoderError" );
      break;
    }
    default:
      ThrowReaderException(CorruptImageError,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -425,7 +425,7 @@
       return(DestroyImageList(image));
     }
   packets=(bits_per_pixel*image->columns+7)/8;
-  pixels=(unsigned char *) AcquireQuantumMemory(packets+256UL,image->rows*
+  pixels=(unsigned char *) AcquireQuantumMemory(packets+257UL,image->rows*
     sizeof(*pixels));
   if (pixels == (unsigned char *) NULL)
     ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
@@ -830,7 +830,7 @@
     image->rows*sizeof(*runlength));
   if (runlength == (unsigned char *) NULL)
     ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
-  buffer=(unsigned char *) AcquireQuantumMemory(256,sizeof(*buffer));
+  buffer=(unsigned char *) AcquireQuantumMemory(257,sizeof(*buffer));
   if (buffer == (unsigned char *) NULL)
     ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
   packet_size=(size_t) (image->depth > 8 ? 2: 1);
```
