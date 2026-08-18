# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5307_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5307_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 493-534 of the vulnerable file.

    if (status == MagickFalse)
      {
        InheritException(exception,&image->exception);
        return(DestroyImageList(image));
      }
    /*
      Allocate VIFF pixels.
    */
    switch ((int) viff_info.data_storage_type)
    {
      case VFF_TYP_2_BYTE: bytes_per_pixel=2; break;
      case VFF_TYP_4_BYTE: bytes_per_pixel=4; break;
      case VFF_TYP_FLOAT: bytes_per_pixel=4; break;
      case VFF_TYP_DOUBLE: bytes_per_pixel=8; break;
      default: bytes_per_pixel=1; break;
    }
    if (viff_info.data_storage_type == VFF_TYP_BIT)
      max_packets=((image->columns+7UL) >> 3UL)*image->rows;
    else
      max_packets=(size_t) (number_pixels*viff_info.number_data_bands);
    pixels=(unsigned char *) AcquireQuantumMemory(max_packets,
      bytes_per_pixel*sizeof(*pixels));
    if (pixels == (unsigned char *) NULL)
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    (void) ReadBlob(image,bytes_per_pixel*max_packets,pixels);
    lsb_first=1;
    if (*(char *) &lsb_first &&
        ((viff_info.machine_dependency != VFF_DEP_DECORDER) &&
         (viff_info.machine_dependency != VFF_DEP_NSORDER)))
      switch ((int) viff_info.data_storage_type)
      {
        case VFF_TYP_2_BYTE:
        {
          MSBOrderShort(pixels,bytes_per_pixel*max_packets);
          break;
        }
        case VFF_TYP_4_BYTE:
        case VFF_TYP_FLOAT:
        {
          MSBOrderLong(pixels,bytes_per_pixel*max_packets);
          break;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -510,8 +510,8 @@
       max_packets=((image->columns+7UL) >> 3UL)*image->rows;
     else
       max_packets=(size_t) (number_pixels*viff_info.number_data_bands);
-    pixels=(unsigned char *) AcquireQuantumMemory(max_packets,
-      bytes_per_pixel*sizeof(*pixels));
+    pixels=(unsigned char *) AcquireQuantumMemory(MagickMax(number_pixels,
+      max_packets),bytes_per_pixel*sizeof(*pixels));
     if (pixels == (unsigned char *) NULL)
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
     (void) ReadBlob(image,bytes_per_pixel*max_packets,pixels);
```
