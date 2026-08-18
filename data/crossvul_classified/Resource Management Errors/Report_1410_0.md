# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1410_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1410_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 190-230 of the vulnerable file.

  if (buffer == (unsigned char *) NULL)
    ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
      image->filename);
  sum=0;
  bits=32;
  p=buffer+0x800;
  for (i=0; i < 3; i++)
  {
    pcd_table[i]=(PCDTable *) NULL;
    pcd_length[i]=0;
  }
  for (i=0; i < (image->columns > 1536 ? 3 : 1); i++)
  {
    PCDGetBits(8);
    length=(sum & 0xff)+1;
    pcd_table[i]=(PCDTable *) AcquireQuantumMemory(length,
      sizeof(*pcd_table[i]));
    if (pcd_table[i] == (PCDTable *) NULL)
      {
        buffer=(unsigned char *) RelinquishMagickMemory(buffer);
        ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
          image->filename);
      }
    r=pcd_table[i];
    for (j=0; j < (ssize_t) length; j++)
    {
      PCDGetBits(8);
      r->length=(unsigned int) (sum & 0xff)+1;
      if (r->length > 16)
        {
          buffer=(unsigned char *) RelinquishMagickMemory(buffer);
          return(MagickFalse);
        }
      PCDGetBits(16);
      r->sequence=(unsigned int) (sum & 0xffff) << 16;
      PCDGetBits(8);
      r->key=(unsigned char) (sum & 0xff);
      r->mask=(~((1U << (32-r->length))-1));
      r++;
    }
    pcd_length[i]=(size_t) length;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -207,6 +207,8 @@
     if (pcd_table[i] == (PCDTable *) NULL)
       {
         buffer=(unsigned char *) RelinquishMagickMemory(buffer);
+        for (j=0; j < i; j++)
+          pcd_table[j]=(PCDTable *) RelinquishMagickMemory(pcd_table[j]);
         ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
           image->filename);
       }
@@ -218,6 +220,8 @@
       if (r->length > 16)
         {
           buffer=(unsigned char *) RelinquishMagickMemory(buffer);
+          for (j=0; j <= i; j++)
+            pcd_table[j]=(PCDTable *) RelinquishMagickMemory(pcd_table[j]);
           return(MagickFalse);
         }
       PCDGetBits(16);
```
