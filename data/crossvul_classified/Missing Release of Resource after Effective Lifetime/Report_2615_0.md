# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2615_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2615_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 3261-3301 of the vulnerable file.

    else
      if ((length == 1) && (quantum == 2))
        {
          if (group == 0x0002)
            datum=ReadBlobLSBSignedShort(image);
          else
            datum=ReadBlobSignedShort(image);
        }
      else
        if ((length == 1) && (quantum == 4))
          {
            if (group == 0x0002)
              datum=ReadBlobLSBSignedLong(image);
            else
              datum=ReadBlobSignedLong(image);
          }
        else
          if ((quantum != 0) && (length != 0))
            {
              if (length > GetBlobSize(image))
                ThrowReaderException(CorruptImageError,
                  "InsufficientImageDataInFile");
              if (~length >= 1)
                data=(unsigned char *) AcquireQuantumMemory(length+1,quantum*
                  sizeof(*data));
              if (data == (unsigned char *) NULL)
                ThrowDCMException(ResourceLimitError,"MemoryAllocationFailed");
              count=ReadBlob(image,(size_t) quantum*length,data);
              if (count != (ssize_t) (quantum*length))
                {
                  if (image_info->verbose != MagickFalse)
                    (void) FormatLocaleFile(stdout,"count=%d quantum=%d "
                      "length=%d group=%d\n",(int) count,(int) quantum,(int)
                      length,(int) group);
                   ThrowDCMException(CorruptImageError,
                     "InsufficientImageDataInFile");
                }
              data[length*quantum]='\0';
            }
          else
            if ((unsigned int) datum == 0xFFFFFFFFU)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3278,7 +3278,7 @@
           if ((quantum != 0) && (length != 0))
             {
               if (length > GetBlobSize(image))
-                ThrowReaderException(CorruptImageError,
+                ThrowDCMException(CorruptImageError,
                   "InsufficientImageDataInFile");
               if (~length >= 1)
                 data=(unsigned char *) AcquireQuantumMemory(length+1,quantum*
```
