# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4779_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4779_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 816-856 of the vulnerable file.

  }
  pdb_image.reserved_1=0;
  pdb_image.note=0;
  pdb_image.x_last=0;
  pdb_image.y_last=0;
  pdb_image.reserved_2=0;
  pdb_image.x_anchor=(unsigned short) 0xffff;
  pdb_image.y_anchor=(unsigned short) 0xffff;
  pdb_image.width=(short) image->columns;
  if (image->columns % 16)
    pdb_image.width=(short) (16*(image->columns/16+1));
  pdb_image.height=(short) image->rows;
  packets=((bits_per_pixel*image->columns+7)/8);
  runlength=(unsigned char *) AcquireQuantumMemory(9UL*packets,
    image->rows*sizeof(*runlength));
  if (runlength == (unsigned char *) NULL)
    ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
  buffer=(unsigned char *) AcquireQuantumMemory(512,sizeof(*buffer));
  if (buffer == (unsigned char *) NULL)
    ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
  packet_size=(size_t) (image->depth > 8 ? 2: 1);
  scanline=(unsigned char *) AcquireQuantumMemory(image->columns,packet_size*
    sizeof(*scanline));
  if (scanline == (unsigned char *) NULL)
    ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
  if (IssRGBCompatibleColorspace(image->colorspace) == MagickFalse)
    (void) TransformImageColorspace(image,sRGBColorspace);
  /*
    Convert to GRAY raster scanline.
  */
  quantum_info=AcquireQuantumInfo(image_info,image);
  if (quantum_info == (QuantumInfo *) NULL)
    ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
  bits=8/(int) bits_per_pixel-1;  /* start at most significant bits */
  literal=0;
  repeat=0;
  q=runlength;
  buffer[0]=0x00;
  for (y=0; y < (ssize_t) image->rows; y++)
  {
    p=GetVirtualPixels(image,0,y,image->columns,1,&image->exception);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -833,7 +833,7 @@
   buffer=(unsigned char *) AcquireQuantumMemory(512,sizeof(*buffer));
   if (buffer == (unsigned char *) NULL)
     ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
-  packet_size=(size_t) (image->depth > 8 ? 2: 1);
+  packet_size=(size_t) (image->depth > 8 ? 2 : 1);
   scanline=(unsigned char *) AcquireQuantumMemory(image->columns,packet_size*
     sizeof(*scanline));
   if (scanline == (unsigned char *) NULL)
@@ -846,6 +846,7 @@
   quantum_info=AcquireQuantumInfo(image_info,image);
   if (quantum_info == (QuantumInfo *) NULL)
     ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
+  status=SetQuantumDepth(image,quantum_info,image->depth > 8 ? 16 : 8);
   bits=8/(int) bits_per_pixel-1;  /* start at most significant bits */
   literal=0;
   repeat=0;
```
