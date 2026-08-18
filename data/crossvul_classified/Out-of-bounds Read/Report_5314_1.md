# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5314_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5314_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 312-352 of the vulnerable file.

  const QuantumInfo *quantum_info,const QuantumType quantum_type)
{
  size_t
    extent,
    packet_size;

  assert(quantum_info != (QuantumInfo *) NULL);
  assert(quantum_info->signature == MagickCoreSignature);
  packet_size=1;
  switch (quantum_type)
  {
    case GrayAlphaQuantum: packet_size=2; break;
    case IndexAlphaQuantum: packet_size=2; break;
    case RGBQuantum: packet_size=3; break;
    case BGRQuantum: packet_size=3; break;
    case RGBAQuantum: packet_size=4; break;
    case RGBOQuantum: packet_size=4; break;
    case BGRAQuantum: packet_size=4; break;
    case CMYKQuantum: packet_size=4; break;
    case CMYKAQuantum: packet_size=5; break;
    default: break;
  }
  extent=MagickMax(image->columns,image->rows);
  if (quantum_info->pack == MagickFalse)
    return((size_t) (packet_size*extent*((quantum_info->depth+7)/8)));
  return((size_t) ((packet_size*extent*quantum_info->depth+7)/8));
}


/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%                                                                             %
%                                                                             %
%                                                                             %
%   G e t Q u a n t u m E n d i a n                                           %
%                                                                             %
%                                                                             %
%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
%  GetQuantumEndian() returns the quantum endian of the image.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -329,6 +329,9 @@
     case BGRAQuantum: packet_size=4; break;
     case CMYKQuantum: packet_size=4; break;
     case CMYKAQuantum: packet_size=5; break;
+    case CbYCrAQuantum: packet_size=4; break;
+    case CbYCrQuantum: packet_size=3; break;
+    case CbYCrYQuantum: packet_size=4; break;
     default: break;
   }
   extent=MagickMax(image->columns,image->rows);
@@ -893,8 +896,6 @@
 }
 
 
-
-
 /*
 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 %                                                                             %
```
