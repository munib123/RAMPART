# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2638_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2638_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1316-1357 of the vulnerable file.

        {
          if(clone_info->file)
          {
            fclose(clone_info->file);
            clone_info->file = NULL;
            (void) remove_utf8(clone_info->filename);
          }
        }
        }

    if (quantum_info != (QuantumInfo *) NULL)
      quantum_info=DestroyQuantumInfo(quantum_info);
    if (clone_info)
      clone_info=DestroyImageInfo(clone_info);
  }

  RelinquishMagickMemory(BImgBuff);
  if (quantum_info != (QuantumInfo *) NULL)
    quantum_info=DestroyQuantumInfo(quantum_info);
END_OF_READING:
  if (clone_info)
    clone_info=DestroyImageInfo(clone_info);
  CloseBlob(image);


  {
    Image *p;
    ssize_t scene=0;

    /*
      Rewind list, removing any empty images while rewinding.
    */
    p=image;
    image=NULL;
    while (p != (Image *) NULL)
      {
        Image *tmp=p;
        if ((p->rows == 0) || (p->columns == 0)) {
          p=p->previous;
          DeleteImageFromList(&tmp);
        } else {
          image=p;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1333,8 +1333,6 @@
   if (quantum_info != (QuantumInfo *) NULL)
     quantum_info=DestroyQuantumInfo(quantum_info);
 END_OF_READING:
-  if (clone_info)
-    clone_info=DestroyImageInfo(clone_info);
   CloseBlob(image);
 
 
@@ -1352,6 +1350,8 @@
         Image *tmp=p;
         if ((p->rows == 0) || (p->columns == 0)) {
           p=p->previous;
+          if (tmp == image2)
+            image2=(Image *) NULL;
           DeleteImageFromList(&tmp);
         } else {
           image=p;
```
