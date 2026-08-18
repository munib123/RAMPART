# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5296_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5296_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 823-863 of the vulnerable file.

            if (packet_size == 1)
              SetPixelIndex(image,ScaleQuantumToChar(pixel),q);
            else
              SetPixelIndex(image,ScaleQuantumToShort(pixel),q);
            SetPixelViaPixelInfo(image,image->colormap+(ssize_t)
              ConstrainColormapIndex(image,GetPixelIndex(image,q),exception),q);
            if (image->depth == 1)
              {
                ssize_t
                  bit,
                  number_bits;
  
                number_bits=image->columns-x;
                if (number_bits > 8)
                  number_bits=8;
                for (bit=0; bit < number_bits; bit++)
                {
                  SetPixelIndex(image,(((unsigned char) pixel) &
                    (0x01 << (7-bit))) != 0 ? 0 : 255,q);
                  SetPixelViaPixelInfo(image,image->colormap+(ssize_t)
                    GetPixelIndex(image,q),q);
                  q+=GetPixelChannels(image);
                  x++;
                }
                x--;
                continue;
              }
          }
        break;
      }
      case 1:
      {
        if (image->storage_class == PseudoClass)
          SetPixelAlpha(image,pixel,q);
        else
          SetPixelGreen(image,pixel,q);
        break;
      }
      case 2:
      {
        if (image->storage_class == PseudoClass)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -840,7 +840,8 @@
                   SetPixelIndex(image,(((unsigned char) pixel) &
                     (0x01 << (7-bit))) != 0 ? 0 : 255,q);
                   SetPixelViaPixelInfo(image,image->colormap+(ssize_t)
-                    GetPixelIndex(image,q),q);
+                    ConstrainColormapIndex(image,GetPixelIndex(image,q),
+                      exception),q);
                   q+=GetPixelChannels(image);
                   x++;
                 }
```
