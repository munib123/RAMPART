# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 364_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `364_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 3215-3255 of the vulnerable file.

            datum=ReadBlobLSBSignedLong(image);
          else
            datum=ReadBlobSignedLong(image);
        }
      else
        if (quantum == 2)
          {
            if (group == 0x0002)
              datum=ReadBlobLSBSignedShort(image);
            else
              datum=ReadBlobSignedShort(image);
          }
      quantum=0;
      length=1;
      if (datum != 0)
        {
          if ((strncmp(implicit_vr,"OW",2) == 0) ||
              (strncmp(implicit_vr,"SS",2) == 0) ||
              (strncmp(implicit_vr,"US",2) == 0))
            quantum=2;
          else 
            if ((strncmp(implicit_vr,"FL",2) == 0) ||
                (strncmp(implicit_vr,"OF",2) == 0) ||
                (strncmp(implicit_vr,"SL",2) == 0) ||
                (strncmp(implicit_vr,"UL",2) == 0))
              quantum=4;
            else 
              if (strncmp(implicit_vr,"FD",2) == 0)
                quantum=8;
              else
                quantum=1;
          if (datum != ~0)
            length=(size_t) datum/quantum;
          else
            {
              /*
                Sequence and item of undefined length.
              */
              quantum=0;
              length=0;
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3232,13 +3232,13 @@
               (strncmp(implicit_vr,"SS",2) == 0) ||
               (strncmp(implicit_vr,"US",2) == 0))
             quantum=2;
-          else 
+          else
             if ((strncmp(implicit_vr,"FL",2) == 0) ||
                 (strncmp(implicit_vr,"OF",2) == 0) ||
                 (strncmp(implicit_vr,"SL",2) == 0) ||
                 (strncmp(implicit_vr,"UL",2) == 0))
               quantum=4;
-            else 
+            else
               if (strncmp(implicit_vr,"FD",2) == 0)
                 quantum=8;
               else
@@ -3884,7 +3884,8 @@
                   "UnexpectedEndOfFile",image->filename);
                 break;
               }
-            (void) fputc(c,file);
+            if (fputc(c,file) != c)
+              break;
           }
           (void) fclose(file);
           if (c == EOF)
@@ -3938,7 +3939,7 @@
         length=(size_t) (GetQuantumRange(info.depth)+1);
         if (length > (size_t) GetBlobSize(image))
           ThrowDCMException(CorruptImageError,"InsufficientImageDataInFile");
-        if (info.scale != (Quantum *) NULL) 
+        if (info.scale != (Quantum *) NULL)
           info.scale=(Quantum *) RelinquishMagickMemory(info.scale);
         info.scale=(Quantum *) AcquireQuantumMemory(MagickMax(length,256),
           sizeof(*info.scale));
```
