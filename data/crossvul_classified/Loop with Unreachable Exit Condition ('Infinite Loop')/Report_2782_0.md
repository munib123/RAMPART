# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 2782_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2782_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 441-483 of the vulnerable file.

    {
      image=DestroyImageList(image);
      return((Image *) NULL);
    }
  (void) ResetMagickMemory(text,0,sizeof(text));
  (void) ReadBlobString(image,text);
  if (LocaleNCompare((char *) text,MagickID,strlen(MagickID)) != 0)
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  do
  {
    width=0;
    height=0;
    max_value=0;
    *colorspace='\0';
    count=(ssize_t) sscanf(text+32,"%lu,%lu,%lu,%s",&width,&height,&max_value,
      colorspace);
    if ((count != 4) || (width == 0) || (height == 0) || (max_value == 0))
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    image->columns=width;
    image->rows=height;
    for (depth=1; (GetQuantumRange(depth)+1) < max_value; depth++)
      if (depth >= 64)
        break;
    image->depth=depth;
    status=SetImageExtent(image,image->columns,image->rows);
    if (status == MagickFalse)
      {
        InheritException(exception,&image->exception);
        return(DestroyImageList(image));
      }
    LocaleLower(colorspace);
    i=(ssize_t) strlen(colorspace)-1;
    image->matte=MagickFalse;
    if ((i > 0) && (colorspace[i] == 'a'))
      {
        colorspace[i]='\0';
        image->matte=MagickTrue;
      }
    type=ParseCommandOption(MagickColorspaceOptions,MagickFalse,colorspace);
    if (type < 0)
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    image->colorspace=(ColorspaceType) type;
    (void) ResetMagickMemory(&pixel,0,sizeof(pixel));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -458,9 +458,9 @@
       ThrowReaderException(CorruptImageError,"ImproperImageHeader");
     image->columns=width;
     image->rows=height;
-    for (depth=1; (GetQuantumRange(depth)+1) < max_value; depth++)
-      if (depth >= 64)
-        break;
+    if ((max_value == 0) || (max_value > 4294967295))
+      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
+    for (depth=1; (GetQuantumRange(depth)+1) < max_value; depth++) ;
     image->depth=depth;
     status=SetImageExtent(image,image->columns,image->rows);
     if (status == MagickFalse)
```
