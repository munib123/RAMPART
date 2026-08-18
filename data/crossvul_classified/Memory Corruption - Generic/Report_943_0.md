# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 943_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `943_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 674-714 of the vulnerable file.

    register const PixelPacket
      *magick_restrict p;

    register ssize_t
      x;

    p=GetVirtualPixels(image,0,offset,image->columns,1,&image->exception);
    if (p == (const PixelPacket *) NULL)
      break;
    indexes=GetVirtualIndexQueue(image);
    if (y == 0)
      {
        waiting_code=(short) (*indexes);
        p++;
      }
    for (x=(ssize_t) (y == 0 ? 1 : 0); x < (ssize_t) image->columns; x++)
    {
      /*
        Probe hash table.
      */
      index=(IndexPacket) ((size_t) GetPixelIndex(indexes+x) & 0xff);
      p++;
      k=(ssize_t) (((size_t) index << (MaxGIFBits-8))+waiting_code);
      if (k >= MaxHashTable)
        k-=MaxHashTable;
      next_pixel=MagickFalse;
      displacement=1;
      if (hash_code[k] > 0)
        {
          if ((hash_prefix[k] == waiting_code) &&
              (hash_suffix[k] == (unsigned char) index))
            {
              waiting_code=hash_code[k];
              continue;
            }
          if (k != 0)
            displacement=MaxHashTable-k;
          for ( ; ; )
          {
            k-=displacement;
            if (k < 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -691,13 +691,15 @@
       /*
         Probe hash table.
       */
+      next_pixel=MagickFalse;
+      displacement=1;
       index=(IndexPacket) ((size_t) GetPixelIndex(indexes+x) & 0xff);
       p++;
       k=(ssize_t) (((size_t) index << (MaxGIFBits-8))+waiting_code);
       if (k >= MaxHashTable)
         k-=MaxHashTable;
-      next_pixel=MagickFalse;
-      displacement=1;
+      if (k < 0)
+        continue;
       if (hash_code[k] > 0)
         {
           if ((hash_prefix[k] == waiting_code) &&
```
