# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4791_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4791_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 922-962 of the vulnerable file.

        }
        else
        {
          if(ImportQuantumPixels(image,(CacheView *) NULL,quantum_info,z2qtype[z],BImgBuff,exception) <= 0)
      goto ImportQuantumPixelsFailed;


          if (z<=1 &&       /* fix only during a last pass z==0 || z==1 */
          (CellType==miINT8 || CellType==miINT16 || CellType==miINT32 || CellType==miINT64))
      FixSignedValues(q,MATLAB_HDR.SizeX);
        }

        if (!SyncAuthenticPixels(image,exception))
  {
    if (logging) (void)LogMagickEvent(CoderEvent,GetMagickModule(),
            "  MAT failed to sync image pixels for a row %u", (unsigned)(MATLAB_HDR.SizeY-i-1));
    goto ExitLoop;
  }
      }
    } while(z-- >= 2);
ExitLoop:


    /* Read complex part of numbers here */
    if (MATLAB_HDR.StructureFlag & FLAG_COMPLEX)
    {        /* Find Min and Max Values for complex parts of floats */
      CellType = ReadBlobXXXLong(image2);    /* Additional object type */
      i = ReadBlobXXXLong(image2);           /* size of a complex part - toss away*/

      if (CellType==miDOUBLE || CellType==miSINGLE)
      {
        CalcMinMax(image2,  image_info->endian, MATLAB_HDR.SizeX, MATLAB_HDR.SizeY, CellType, ldblk, BImgBuff, &MinVal, &MaxVal);
      }

      if (CellType==miDOUBLE)
        for (i = 0; i < (ssize_t) MATLAB_HDR.SizeY; i++)
  {
          ReadBlobDoublesXXX(image2, ldblk, (double *)BImgBuff);
          InsertComplexDoubleRow((double *)BImgBuff, i, image, MinVal, MaxVal);
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -939,6 +939,7 @@
   }
       }
     } while(z-- >= 2);
+    quantum_info=DestroyQuantumInfo(quantum_info);
 ExitLoop:
 
 
```
