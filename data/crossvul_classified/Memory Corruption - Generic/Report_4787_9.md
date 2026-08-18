# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4787_9
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4787_9`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 358-398 of the vulnerable file.

      EncodedByte-=i+1;
      ldblk+=(ssize_t) RunCountMasked;

      RunCount=(unsigned char) ReadBlobByte(image);
      if(EOFBlob(image) != MagickFalse)  goto CUT_KO;  /*wrong data: unexpected eof in line*/
      RunCountMasked=RunCount & 0x7F;
    }
  if(EncodedByte!=1) goto CUT_KO;  /*wrong data: size incorrect*/
  i=0;        /*guess a number of bit planes*/
  if(ldblk==(int) Header.Width)   i=8;
  if(2*ldblk==(int) Header.Width) i=4;
  if(8*ldblk==(int) Header.Width) i=1;
  if(i==0) goto CUT_KO;    /*wrong data: incorrect bit planes*/
  depth=i;

  image->columns=Header.Width;
  image->rows=Header.Height;
  image->depth=8;
  image->colors=(size_t) (GetQuantumRange(1UL*i)+1);

  if (image_info->ping) goto Finish;

  /* ----- Do something with palette ----- */
  if ((clone_info=CloneImageInfo(image_info)) == NULL) goto NoPalette;


  i=(ssize_t) strlen(clone_info->filename);
  j=i;
  while(--i>0)
    {
      if(clone_info->filename[i]=='.')
        {
          break;
        }
      if(clone_info->filename[i]=='/' || clone_info->filename[i]=='\\' ||
         clone_info->filename[i]==':' )
        {
          i=j;
          break;
        }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -375,7 +375,13 @@
   image->depth=8;
   image->colors=(size_t) (GetQuantumRange(1UL*i)+1);
 
-  if (image_info->ping) goto Finish;
+  if (image_info->ping != MagickFalse) goto Finish;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
 
   /* ----- Do something with palette ----- */
   if ((clone_info=CloneImageInfo(image_info)) == NULL) goto NoPalette;
```
