# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 950_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `950_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 255-295 of the vulnerable file.

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
    {
      annotate_info=DestroyDrawInfo(annotate_info);
      annotate=DestroyDrawInfo(annotate);
      return(MagickFalse);
    }
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -272,6 +272,7 @@
     {
       annotate_info=DestroyDrawInfo(annotate_info);
       annotate=DestroyDrawInfo(annotate);
+      text=DestroyString(text);
       return(MagickFalse);
     }
   p=text;
@@ -306,6 +307,7 @@
       annotate_info=DestroyDrawInfo(annotate_info);
       annotate=DestroyDrawInfo(annotate);
       textlist=(char **) RelinquishMagickMemory(textlist);
+      text=DestroyString(text);
       return(MagickFalse);
     }
   if (IsGrayColorspace(image->colorspace) != MagickFalse)
@@ -523,6 +525,7 @@
   annotate_info=DestroyDrawInfo(annotate_info);
   annotate=DestroyDrawInfo(annotate);
   textlist=(char **) RelinquishMagickMemory(textlist);
+  text=DestroyString(text);
   return(status);
 }
 
```
