# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 5310_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5310_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 681-721 of the vulnerable file.

  assert(image->signature == MagickSignature);
  if (image->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
  assert(quantum_info != (QuantumInfo *) NULL);
  assert(quantum_info->signature == MagickSignature);
  quantum_info->depth=depth;
  if (quantum_info->format == FloatingPointQuantumFormat)
    {
      if (quantum_info->depth > 32)
        quantum_info->depth=64;
      else
        if (quantum_info->depth > 16)
          quantum_info->depth=32;
        else
          quantum_info->depth=16;
    }
  if (quantum_info->pixels != (unsigned char **) NULL)
    DestroyQuantumPixels(quantum_info);
  quantum=(quantum_info->pad+6)*(quantum_info->depth+7)/8;
  extent=image->columns*quantum;
  if (quantum != (extent/image->columns))
    return(MagickFalse);
  return(AcquireQuantumPixels(quantum_info,extent));
}


/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%                                                                             %
%                                                                             %
%                                                                             %
%   S e t Q u a n t u m E n d i a n                                           %
%                                                                             %
%                                                                             %
%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
%  SetQuantumEndian() sets the quantum endian.
%
%  The endian of the SetQuantumEndian method is:
%
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -698,7 +698,7 @@
     DestroyQuantumPixels(quantum_info);
   quantum=(quantum_info->pad+6)*(quantum_info->depth+7)/8;
   extent=image->columns*quantum;
-  if (quantum != (extent/image->columns))
+  if ((image->columns != 0) && (quantum != (extent/image->columns)))
     return(MagickFalse);
   return(AcquireQuantumPixels(quantum_info,extent));
 }
```
