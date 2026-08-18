# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 1834_5
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1834_5`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 170-211 of the vulnerable file.


  register ssize_t
    i;

  size_t
    sizes[MAX_SIZES]={256,192,128,96,64,48,40,32,24,16};

  images=NULL;
  *count=0;
  i=0;
  p=option;
  while (*p != '\0' && i < MAX_SIZES)
  {
    size_t
      size;

    while ((isspace((int) ((unsigned char) *p)) != 0))
      p++;

    size=(size_t)strtol(p,&q,10);
    if (p == q || size < 16 || size > 256)
        return((Image *) NULL);

    p=q;
    sizes[i++]=size;

    while ((isspace((int) ((unsigned char) *p)) != 0) || (*p == ','))
      p++;
  }

  if (i==0)
    i=10;
  *count=i;
  for (i=0; i < *count; i++)
  {
    resized=ResizeImage(image,sizes[i],sizes[i],image->filter,exception);
    if (resized == (Image *) NULL)
      return(DestroyImageList(images));

    if (images == (Image *) NULL)
      images=resized;
    else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -187,8 +187,8 @@
       p++;
 
     size=(size_t)strtol(p,&q,10);
-    if (p == q || size < 16 || size > 256)
-        return((Image *) NULL);
+    if ((p == q) || (size < 16) || (size > 256))
+      return((Image *) NULL);
 
     p=q;
     sizes[i++]=size;
@@ -359,6 +359,8 @@
           Icon image encoded as a compressed PNG image.
         */
         length=icon_file.directory[i].size;
+        if (~length < 16)
+          ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
         png=(unsigned char *) AcquireQuantumMemory(length+16,sizeof(*png));
         if (png == (unsigned char *) NULL)
           ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
```
