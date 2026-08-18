# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1186_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1186_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 6169-6209 of the vulnerable file.

      alpha=fabs(primitive_info[j].point.x-primitive_info[i].point.x);
      if (alpha > (double) SSIZE_MAX)
        {
          (void) ThrowMagickException(mvg_info->exception,GetMagickModule(),
            ResourceLimitError,"MemoryAllocationFailed","`%s'","");
          return(MagickFalse);
        }
      if (alpha > (double) quantum)
        quantum=(size_t) alpha;
      alpha=fabs(primitive_info[j].point.y-primitive_info[i].point.y);
      if (alpha > (double) SSIZE_MAX)
        {
          (void) ThrowMagickException(mvg_info->exception,GetMagickModule(),
            ResourceLimitError,"MemoryAllocationFailed","`%s'","");
          return(MagickFalse);
        }
      if (alpha > (double) quantum)
        quantum=(size_t) alpha;
    }
  }
  quantum=MagickMin(quantum/number_coordinates,BezierQuantum);
  primitive_info=(*mvg_info->primitive_info)+mvg_info->offset;
  coefficients=(double *) AcquireQuantumMemory(number_coordinates,
    sizeof(*coefficients));
  points=(PointInfo *) AcquireQuantumMemory(quantum,number_coordinates*
    sizeof(*points));
  if ((coefficients == (double *) NULL) || (points == (PointInfo *) NULL))
    {
      if (points != (PointInfo *) NULL)
        points=(PointInfo *) RelinquishMagickMemory(points);
      if (coefficients != (double *) NULL)
        coefficients=(double *) RelinquishMagickMemory(coefficients);
      (void) ThrowMagickException(mvg_info->exception,GetMagickModule(),
        ResourceLimitError,"MemoryAllocationFailed","`%s'","");
      return(MagickFalse);
    }
  control_points=quantum*number_coordinates;
  if (CheckPrimitiveExtent(mvg_info,control_points+1) == MagickFalse)
    {
      points=(PointInfo *) RelinquishMagickMemory(points);
      coefficients=(double *) RelinquishMagickMemory(coefficients);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6186,8 +6186,8 @@
         quantum=(size_t) alpha;
     }
   }
+  primitive_info=(*mvg_info->primitive_info)+mvg_info->offset;
   quantum=MagickMin(quantum/number_coordinates,BezierQuantum);
-  primitive_info=(*mvg_info->primitive_info)+mvg_info->offset;
   coefficients=(double *) AcquireQuantumMemory(number_coordinates,
     sizeof(*coefficients));
   points=(PointInfo *) AcquireQuantumMemory(quantum,number_coordinates*
@@ -6209,6 +6209,7 @@
       coefficients=(double *) RelinquishMagickMemory(coefficients);
       return(MagickFalse);
     }
+  primitive_info=(*mvg_info->primitive_info)+mvg_info->offset;
   /*
     Compute bezier points.
   */
```
