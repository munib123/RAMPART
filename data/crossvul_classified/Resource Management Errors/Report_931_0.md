# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 931_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `931_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 263-303 of the vulnerable file.

  assert(image != (Image *) NULL);
  assert(image->signature == MagickCoreSignature);
  if (image->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
  assert(draw_info != (DrawInfo *) NULL);
  assert(draw_info->signature == MagickCoreSignature);
  if (draw_info->text == (char *) NULL)
    return(MagickFalse);
  if (*draw_info->text == '\0')
    return(MagickTrue);
  annotate=CloneDrawInfo((ImageInfo *) NULL,draw_info);
  text=annotate->text;
  annotate->text=(char *) NULL;
  annotate_info=CloneDrawInfo((ImageInfo *) NULL,draw_info);
  number_lines=1;
  for (p=text; *p != '\0'; p++)
    if (*p == '\n')
      number_lines++;
  textlist=AcquireQuantumMemory(number_lines+1,sizeof(*textlist));
  if (textlist == (char **) NULL)
    return(MagickFalse);
  p=text;
  for (i=0; i < number_lines; i++)
  {
    char
      *q;

    textlist[i]=p;
    for (q=p; *q != '\0'; q++)
      if ((*q == '\r') || (*q == '\n'))
        break;
    if (*q == '\r')
      {
        *q='\0';
        q++;
      }
    *q='\0';
    p=q+1;
  }
  textlist[i]=(char *) NULL;
  SetGeometry(image,&geometry);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -280,7 +280,11 @@
       number_lines++;
   textlist=AcquireQuantumMemory(number_lines+1,sizeof(*textlist));
   if (textlist == (char **) NULL)
-    return(MagickFalse);
+    {
+      annotate_info=DestroyDrawInfo(annotate_info);
+      annotate=DestroyDrawInfo(annotate);
+      return(MagickFalse);
+    }
   p=text;
   for (i=0; i < number_lines; i++)
   {
@@ -309,7 +313,12 @@
       (void) ParseGeometry(annotate_info->geometry,&geometry_info);
     }
   if (SetImageStorageClass(image,DirectClass,exception) == MagickFalse)
-    return(MagickFalse);
+    {
+      annotate_info=DestroyDrawInfo(annotate_info);
+      annotate=DestroyDrawInfo(annotate);
+      textlist=(char **) RelinquishMagickMemory(textlist);
+      return(MagickFalse);
+    }
   if (IsGrayColorspace(image->colorspace) != MagickFalse)
     (void) SetImageColorspace(image,sRGBColorspace,exception);
   status=MagickTrue;
```
