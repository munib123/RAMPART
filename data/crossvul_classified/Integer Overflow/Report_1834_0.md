# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 1834_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1834_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 599-639 of the vulnerable file.

  if (AcquireMagickResource(MemoryResource,length) != MagickFalse)
    {
      memory_info->blob=AcquireAlignedMemory(1,length);
      if (memory_info->blob != NULL)
        memory_info->type=AlignedVirtualMemory;
      else
        RelinquishMagickResource(MemoryResource,length);
    }
  if ((memory_info->blob == NULL) &&
      (AcquireMagickResource(MapResource,length) != MagickFalse))
    {
      /*
        Heap memory failed, try anonymous memory mapping.
      */
      memory_info->blob=MapBlob(-1,IOMode,0,length);
      if (memory_info->blob != NULL)
        memory_info->type=MapVirtualMemory;
      else
        RelinquishMagickResource(MapResource,length);
    }
  if (memory_info->blob == NULL)
    {
      int
        file;

      /*
        Anonymous memory mapping failed, try file-backed memory mapping.
      */
      file=AcquireUniqueFileResource(memory_info->filename);
      if (file != -1)
        {
          if ((lseek(file,length-1,SEEK_SET) >= 0) && (write(file,"",1) == 1))
            {
              memory_info->blob=MapBlob(file,IOMode,0,length);
              if (memory_info->blob != NULL)
                {
                  memory_info->type=MapVirtualMemory;
                  (void) AcquireMagickResource(MapResource,length);
                }
            }
          (void) close(file);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -616,7 +616,8 @@
       else
         RelinquishMagickResource(MapResource,length);
     }
-  if (memory_info->blob == NULL)
+  if ((memory_info->blob == NULL) &&
+      (AcquireMagickResource(DiskResource,length) != MagickFalse))
     {
       int
         file;
@@ -625,15 +626,26 @@
         Anonymous memory mapping failed, try file-backed memory mapping.
       */
       file=AcquireUniqueFileResource(memory_info->filename);
-      if (file != -1)
+      if (file == -1)
+        RelinquishMagickResource(DiskResource,length);
+      else
         {
-          if ((lseek(file,length-1,SEEK_SET) >= 0) && (write(file,"",1) == 1))
+          if ((lseek(file,length-1,SEEK_SET) < 0) || (write(file,"",1) != 1))
+            RelinquishMagickResource(DiskResource,length);
+          else
             {
-              memory_info->blob=MapBlob(file,IOMode,0,length);
-              if (memory_info->blob != NULL)
+              if (AcquireMagickResource(MapResource,length) == MagickFalse)
+                RelinquishMagickResource(DiskResource,length);
+              else
                 {
-                  memory_info->type=MapVirtualMemory;
-                  (void) AcquireMagickResource(MapResource,length);
+                  memory_info->blob=MapBlob(file,IOMode,0,length);
+                  if (memory_info->blob != NULL)
+                    memory_info->type=MapVirtualMemory;
+                  else
+                    {
+                      RelinquishMagickResource(MapResource,length);
+                      RelinquishMagickResource(DiskResource,length);
+                    }
                 }
             }
           (void) close(file);
@@ -1051,7 +1063,10 @@
         memory_info->blob=NULL;
         RelinquishMagickResource(MapResource,memory_info->length);
         if (*memory_info->filename != '\0')
-          (void) RelinquishUniqueFileResource(memory_info->filename);
+          {
+            (void) RelinquishUniqueFileResource(memory_info->filename);
+            RelinquishMagickResource(DiskResource,memory_info->length);
+          }
         break;
       }
       case UnalignedVirtualMemory:
```
