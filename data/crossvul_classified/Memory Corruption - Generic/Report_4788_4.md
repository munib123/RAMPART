# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4788_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4788_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 223-278 of the vulnerable file.

%   A c q u i r e A l i g n e d M e m o r y                                   %
%                                                                             %
%                                                                             %
%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
%  AcquireAlignedMemory() returns a pointer to a block of memory at least size
%  bytes whose address is a multiple of 16*sizeof(void *).
%
%  The format of the AcquireAlignedMemory method is:
%
%      void *AcquireAlignedMemory(const size_t count,const size_t quantum)
%
%  A description of each parameter follows:
%
%    o count: the number of quantum elements to allocate.
%
%    o quantum: the number of bytes in each quantum.
%
*/

static MagickBooleanType CheckMemoryOverflow(const size_t count,
  const size_t quantum)
{
  size_t
    size;

  size=count*quantum;
  if ((count == 0) || (quantum != (size/count)))
    {
      errno=ENOMEM;
      return(MagickTrue);
    }
  return(MagickFalse);
}

MagickExport void *AcquireAlignedMemory(const size_t count,const size_t quantum)
{
#define AlignedExtent(size,alignment) \
  (((size)+((alignment)-1)) & ~((alignment)-1))

  size_t
    alignment,
    extent,
    size;

  void
    *memory;

  if (CheckMemoryOverflow(count,quantum) != MagickFalse)
    return((void *) NULL);
  memory=NULL;
  alignment=CACHE_LINE_SIZE;
  size=count*quantum;
  extent=AlignedExtent(size,alignment);
  if ((size == 0) || (alignment < sizeof(void *)) || (extent < size))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -240,22 +240,6 @@
 %    o quantum: the number of bytes in each quantum.
 %
 */
-
-static MagickBooleanType CheckMemoryOverflow(const size_t count,
-  const size_t quantum)
-{
-  size_t
-    size;
-
-  size=count*quantum;
-  if ((count == 0) || (quantum != (size/count)))
-    {
-      errno=ENOMEM;
-      return(MagickTrue);
-    }
-  return(MagickFalse);
-}
-
 MagickExport void *AcquireAlignedMemory(const size_t count,const size_t quantum)
 {
 #define AlignedExtent(size,alignment) \
@@ -269,7 +253,7 @@
   void
     *memory;
 
-  if (CheckMemoryOverflow(count,quantum) != MagickFalse)
+  if (HeapOverflowSanityCheck(count,quantum) != MagickFalse)
     return((void *) NULL);
   memory=NULL;
   alignment=CACHE_LINE_SIZE;
@@ -553,7 +537,7 @@
   size_t
     extent;
 
-  if (CheckMemoryOverflow(count,quantum) != MagickFalse)
+  if (HeapOverflowSanityCheck(count,quantum) != MagickFalse)
     return((void *) NULL);
   extent=count*quantum;
   return(AcquireMagickMemory(extent));
@@ -594,7 +578,7 @@
   size_t
     extent;
 
-  if (CheckMemoryOverflow(count,quantum) != MagickFalse)
+  if (HeapOverflowSanityCheck(count,quantum) != MagickFalse)
     return((MemoryInfo *) NULL);
   memory_info=(MemoryInfo *) MagickAssumeAligned(AcquireAlignedMemory(1,
     sizeof(*memory_info)));
@@ -933,6 +917,46 @@
 %                                                                             %
 %                                                                             %
 %                                                                             %
++   H e a p O v e r f l o w S a n i t y C h e c k                             %
+%                                                                             %
+%                                                                             %
+%                                                                             %
+%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
+%
+%  HeapOverflowSanityCheck() returns MagickTrue if the heap allocation request
+%  does not exceed the maximum limits of a size_t otherwise MagickFalse.
+%
+%  The format of the HeapOverflowSanityCheck method is:
+%
+%      MagickBooleanType HeapOverflowSanityCheck(const size_t count,
+%        const size_t quantum)
+%
+%  A description of each parameter follows:
+%
+%    o size: the size of the memory in bytes we require.
+%
+*/
+MagickExport MagickBooleanType HeapOverflowSanityCheck(const size_t count,
+  const size_t quantum)
+{
+  size_t
+    size;
+
+  size=count*quantum;
+  if ((count == 0) || (quantum != (size/count)))
+    {
+      errno=ENOMEM;
+      return(MagickTrue);
+    }
+  return(MagickFalse);
+}
+
+
+/*
+%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
+%                                                                             %
+%                                                                             %
+%                                                                             %
 %   R e l i n q u i s h A l i g n e d M e m o r y                             %
 %                                                                             %
 %                                                                             %
@@ -1243,7 +1267,7 @@
   size_t
     extent;
 
-  if (CheckMemoryOverflow(count,quantum) != MagickFalse)
+  if (HeapOverflowSanityCheck(count,quantum) != MagickFalse)
     {
       memory=RelinquishMagickMemory(memory);
       return((void *) NULL);
```
