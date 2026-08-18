# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4425_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4425_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 243-283 of the vulnerable file.

    }
    case AddEvaluateOperator:
    {
      result=(MagickRealType) (pixel+value);
      break;
    }
    case AddModulusEvaluateOperator:
    {
      /*
        This returns a 'floored modulus' of the addition which is a
        positive result.  It differs from  % or fmod() which returns a
        'truncated modulus' result, where floor() is replaced by trunc()
        and could return a negative result (which is clipped).
      */
      result=pixel+value;
      result-=(QuantumRange+1.0)*floor((double) result/(QuantumRange+1.0));
      break;
    }
    case AndEvaluateOperator:
    {
      result=(MagickRealType) ((size_t) pixel & (size_t) (value+0.5));
      break;
    }
    case CosineEvaluateOperator:
    {
      result=(MagickRealType) (QuantumRange*(0.5*cos((double) (2.0*MagickPI*
        QuantumScale*pixel*value))+0.5));
      break;
    }
    case DivideEvaluateOperator:
    {
      result=pixel/(value == 0.0 ? 1.0 : value);
      break;
    }
    case ExponentialEvaluateOperator:
    {
      result=(MagickRealType) (QuantumRange*exp((double) (value*QuantumScale*
        pixel)));
      break;
    }
    case GaussianNoiseEvaluateOperator:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -260,7 +260,7 @@
     }
     case AndEvaluateOperator:
     {
-      result=(MagickRealType) ((size_t) pixel & (size_t) (value+0.5));
+      result=(MagickRealType) ((ssize_t) pixel & (ssize_t) (value+0.5));
       break;
     }
     case CosineEvaluateOperator:
@@ -300,7 +300,7 @@
     }
     case LeftShiftEvaluateOperator:
     {
-      result=(MagickRealType) ((size_t) pixel << (size_t) (value+0.5));
+      result=(MagickRealType) ((ssize_t) pixel << (ssize_t) (value+0.5));
       break;
     }
     case LogEvaluateOperator:
@@ -343,7 +343,7 @@
     }
     case OrEvaluateOperator:
     {
-      result=(MagickRealType) ((size_t) pixel | (size_t) (value+0.5));
+      result=(MagickRealType) ((ssize_t) pixel | (ssize_t) (value+0.5));
       break;
     }
     case PoissonNoiseEvaluateOperator:
@@ -360,7 +360,7 @@
     }
     case RightShiftEvaluateOperator:
     {
-      result=(MagickRealType) ((size_t) pixel >> (size_t) (value+0.5));
+      result=(MagickRealType) ((ssize_t) pixel >> (ssize_t) (value+0.5));
       break;
     }
     case RootMeanSquareEvaluateOperator:
@@ -414,7 +414,7 @@
     }
     case XorEvaluateOperator:
     {
-      result=(MagickRealType) ((size_t) pixel ^ (size_t) (value+0.5));
+      result=(MagickRealType) ((ssize_t) pixel ^ (ssize_t) (value+0.5));
       break;
     }
   }
```
