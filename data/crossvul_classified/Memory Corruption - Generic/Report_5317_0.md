# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 5317_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5317_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 2532-2574 of the vulnerable file.

    short_sans;

  length=GetStringInfoLength(bim_profile);
  if (length < 16)
    return;
  datum=GetStringInfoDatum(bim_profile);
  for (p=datum; (p >= datum) && (p < (datum+length-16)); )
  {
    register unsigned char
      *q;

    q=(unsigned char *) p;
    if (LocaleNCompare((const char *) p,"8BIM",4) != 0)
      break;
    p=PushLongPixel(MSBEndian,p,&long_sans);
    p=PushShortPixel(MSBEndian,p,&id);
    p=PushShortPixel(MSBEndian,p,&short_sans);
    p=PushLongPixel(MSBEndian,p,&count);
    if (id == 0x0000040f)
      {
        (void) CopyMagickMemory(q,q+PSDQuantum(count)+12,length-
          (PSDQuantum(count)+12)-(q-datum));
        SetStringInfoLength(bim_profile,length-(PSDQuantum(count)+12));
        break;
      }
    p+=count;
    if ((count & 0x01) != 0)
      p++;
  }
}

static void RemoveResolutionFromResourceBlock(StringInfo *bim_profile)
{
  register const unsigned char
    *p;

  size_t
    length;

  unsigned char
    *datum;

  unsigned int
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2549,9 +2549,12 @@
     p=PushLongPixel(MSBEndian,p,&count);
     if (id == 0x0000040f)
       {
-        (void) CopyMagickMemory(q,q+PSDQuantum(count)+12,length-
-          (PSDQuantum(count)+12)-(q-datum));
-        SetStringInfoLength(bim_profile,length-(PSDQuantum(count)+12));
+        if ((q+PSDQuantum(count)+12) < (datum+length-16))
+          {
+            (void) CopyMagickMemory(q,q+PSDQuantum(count)+12,length-
+              (PSDQuantum(count)+12)-(q-datum));
+            SetStringInfoLength(bim_profile,length-(PSDQuantum(count)+12));
+          }
         break;
       }
     p+=count;
```
