# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in c
**Pair ID:** 2614_0
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2614_0`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```c
Lines 4290-4330 of the vulnerable file.

      break;

    type[0]='\0';
    (void) ConcatenateMagickString(type,"errr",MaxTextExtent);
    length=ReadBlobMSBLong(image);
    count=(unsigned int) ReadBlob(image,4,(unsigned char *) type);

    if (logging != MagickFalse)
      (void) LogMagickEvent(CoderEvent,GetMagickModule(),
        "  Reading JNG chunk type %c%c%c%c, length: %.20g",
        type[0],type[1],type[2],type[3],(double) length);

    if (length > PNG_UINT_31_MAX || count == 0)
      ThrowReaderException(CorruptImageError,"CorruptImage");

    p=NULL;
    chunk=(unsigned char *) NULL;

    if (length != 0)
      {
        chunk=(unsigned char *) AcquireQuantumMemory(length+MagickPathExtent,
          sizeof(*chunk));

        if (chunk == (unsigned char *) NULL)
          ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");

        for (i=0; i < (ssize_t) length; i++)
        {
          int
            c;

          c=ReadBlobByte(image);
          if (c == EOF)
            break;
          chunk[i]=(unsigned char) c;
        }

        p=chunk;
      }

    (void) ReadBlobMSBLong(image);  /* read crc word */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4307,6 +4307,8 @@
 
     if (length != 0)
       {
+        if (length > GetBlobSize(image))
+          ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
         chunk=(unsigned char *) AcquireQuantumMemory(length+MagickPathExtent,
           sizeof(*chunk));
 
@@ -5175,6 +5177,9 @@
 
         if (length != 0)
           {
+            if (length > GetBlobSize(image))
+              ThrowReaderException(CorruptImageError,
+                "InsufficientImageDataInFile");
             chunk=(unsigned char *) AcquireQuantumMemory(length+
               MagickPathExtent,sizeof(*chunk));
 
```
