# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4790_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4790_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 928-968 of the vulnerable file.

    MATLAB_HDR.unknown3 = ReadBlobXXXLong(image2);
    if(image!=image2)
      MATLAB_HDR.unknown4 = ReadBlobXXXLong(image2);  /* ??? don't understand why ?? */
    MATLAB_HDR.unknown4 = ReadBlobXXXLong(image2);
    MATLAB_HDR.DimFlag = ReadBlobXXXLong(image2);
    MATLAB_HDR.SizeX = ReadBlobXXXLong(image2);
    MATLAB_HDR.SizeY = ReadBlobXXXLong(image2);


    switch(MATLAB_HDR.DimFlag)
    {
      case  8: z2=z=1; break;      /* 2D matrix*/
      case 12: z2=z = ReadBlobXXXLong(image2);  /* 3D matrix RGB*/
           Unknown6 = ReadBlobXXXLong(image2);
           (void) Unknown6;
         if(z!=3) ThrowReaderException(CoderError, "MultidimensionalMatricesAreNotSupported");
         break;
      case 16: z2=z = ReadBlobXXXLong(image2);  /* 4D matrix animation */
         if(z!=3 && z!=1)
           ThrowReaderException(CoderError, "MultidimensionalMatricesAreNotSupported");
          Frames = ReadBlobXXXLong(image2);
         break;
      default: ThrowReaderException(CoderError, "MultidimensionalMatricesAreNotSupported");
    }

    MATLAB_HDR.Flag1 = ReadBlobXXXShort(image2);
    MATLAB_HDR.NameFlag = ReadBlobXXXShort(image2);

    if (logging) (void)LogMagickEvent(CoderEvent,GetMagickModule(),
          "MATLAB_HDR.StructureClass %d",MATLAB_HDR.StructureClass);
    if (MATLAB_HDR.StructureClass != mxCHAR_CLASS &&
        MATLAB_HDR.StructureClass != mxSINGLE_CLASS &&    /* float + complex float */
        MATLAB_HDR.StructureClass != mxDOUBLE_CLASS &&    /* double + complex double */
        MATLAB_HDR.StructureClass != mxINT8_CLASS &&
        MATLAB_HDR.StructureClass != mxUINT8_CLASS &&    /* uint8 + uint8 3D */
        MATLAB_HDR.StructureClass != mxINT16_CLASS &&
        MATLAB_HDR.StructureClass != mxUINT16_CLASS &&    /* uint16 + uint16 3D */
        MATLAB_HDR.StructureClass != mxINT32_CLASS &&
        MATLAB_HDR.StructureClass != mxUINT32_CLASS &&    /* uint32 + uint32 3D */
        MATLAB_HDR.StructureClass != mxINT64_CLASS &&
        MATLAB_HDR.StructureClass != mxUINT64_CLASS)    /* uint64 + uint64 3D */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -945,7 +945,9 @@
       case 16: z2=z = ReadBlobXXXLong(image2);  /* 4D matrix animation */
          if(z!=3 && z!=1)
            ThrowReaderException(CoderError, "MultidimensionalMatricesAreNotSupported");
-          Frames = ReadBlobXXXLong(image2);
+         Frames = ReadBlobXXXLong(image2);
+         if (Frames == 0)
+           ThrowReaderException(CorruptImageError,"ImproperImageHeader");
          break;
       default: ThrowReaderException(CoderError, "MultidimensionalMatricesAreNotSupported");
     }
```
