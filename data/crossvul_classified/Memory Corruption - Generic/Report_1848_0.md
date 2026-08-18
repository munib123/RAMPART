# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1848_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1848_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2290-2330 of the vulnerable file.

              {
                pixel=QuantumRange*(Sa*(Da+Sa*(Dca-Da)/(2.0*Sca))+Sca*(1.0-Da)+
                  Dca*(1.0-Sa));
                break;
              }
            pixel=QuantumRange*(Dca*Sa*Sa/(2.0*(Sa-Sca))+Sca*(1.0-Da)+Dca*
              (1.0-Sa));
            break;
          }
          case XorCompositeOp:
          {
            pixel=QuantumRange*(Sca*(1.0-Da)+Dca*(1.0-Sa));
            break;
          }
          default:
          {
            pixel=Sc;
            break;
          }
        }
        q[i]=ClampToQuantum(pixel);
      }
      p+=GetPixelChannels(composite_image);
      channels=GetPixelChannels(composite_image);
      if (p >= (pixels+channels*composite_image->columns))
        p=pixels;
      q+=GetPixelChannels(image);
    }
    if (SyncCacheViewAuthenticPixels(image_view,exception) == MagickFalse)
      status=MagickFalse;
    if (image->progress_monitor != (MagickProgressMonitor) NULL)
      {
        MagickBooleanType
          proceed;

#if defined(MAGICKCORE_OPENMP_SUPPORT)
        #pragma omp critical (MagickCore_CompositeImage)
#endif
        proceed=SetImageProgress(image,CompositeImageTag,progress++,
          image->rows);
        if (proceed == MagickFalse)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2307,7 +2307,7 @@
             break;
           }
         }
-        q[i]=ClampToQuantum(pixel);
+        q[i]=ClampPixel(pixel);
       }
       p+=GetPixelChannels(composite_image);
       channels=GetPixelChannels(composite_image);
```
