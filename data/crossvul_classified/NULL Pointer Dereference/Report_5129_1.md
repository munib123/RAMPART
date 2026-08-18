# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5129_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5129_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 3203-3243 of the vulnerable file.

        }
        break;
      }
      case 0x0028:
      {
        switch (element)
        {
          case 0x0002:
          {
            /*
              Samples per pixel.
            */
            samples_per_pixel=(size_t) datum;
            break;
          }
          case 0x0004:
          {
            /*
              Photometric interpretation.
            */
            for (i=0; i < (ssize_t) MagickMin(length,MagickPathExtent-1); i++)
              photometric[i]=(char) data[i];
            photometric[i]='\0';
            polarity=LocaleCompare(photometric,"MONOCHROME1 ") == 0 ?
              MagickTrue : MagickFalse;
            break;
          }
          case 0x0006:
          {
            /*
              Planar configuration.
            */
            if (datum == 1)
              image->interlace=PlaneInterlace;
            break;
          }
          case 0x0008:
          {
            /*
              Number of frames.
            */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3220,6 +3220,8 @@
             /*
               Photometric interpretation.
             */
+            if (data == (unsigned char *) NULL)
+              break;
             for (i=0; i < (ssize_t) MagickMin(length,MagickPathExtent-1); i++)
               photometric[i]=(char) data[i];
             photometric[i]='\0';
@@ -3241,6 +3243,8 @@
             /*
               Number of frames.
             */
+            if (data == (unsigned char *) NULL)
+              break;
             number_scenes=StringToUnsignedLong((char *) data);
             break;
           }
@@ -3678,7 +3682,7 @@
       if (scale == (Quantum *) NULL)
         ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
       range=GetQuantumRange(depth);
-      for (i=0; i < (ssize_t) (GetQuantumRange(depth)+1); i++)
+      for (i=0; i <= (ssize_t) GetQuantumRange(depth); i++)
         scale[i]=ScaleAnyToQuantum((size_t) i,range);
     }
   if (image->compression == RLECompression)
@@ -3969,9 +3973,12 @@
                 pixel.blue&=mask;
                 if (scale != (Quantum *) NULL)
                   {
-                    pixel.red=scale[pixel.red];
-                    pixel.green=scale[pixel.green];
-                    pixel.blue=scale[pixel.blue];
+                    if (pixel.red <= GetQuantumRange(depth))
+                      pixel.red=scale[pixel.red];
+                    if (pixel.green <= GetQuantumRange(depth))
+                      pixel.green=scale[pixel.green];
+                    if (pixel.blue <= GetQuantumRange(depth))
+                      pixel.blue=scale[pixel.blue];
                   }
               }
             SetPixelRed(image,(Quantum) pixel.red,q);
```
