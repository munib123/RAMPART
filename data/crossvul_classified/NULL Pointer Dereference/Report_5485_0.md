# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5485_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5485_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 199-239 of the vulnerable file.

        clone_image->properties,(void *(*)(void *)) ConstantString,
        (void *(*)(void *)) ConstantString);
    }
  return(MagickTrue);
}


/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%                                                                             %
%                                                                             %
%                                                                             %
%   D e f i n e I m a g e P r o p e r t y                                     %
%                                                                             %
%                                                                             %
%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
%  DefineImageProperty() associates an assignment string of the form
%  "key=value" with an artifact or options. It is equivelent to
%  SetImageProperty()
%
%  The format of the DefineImageProperty method is:
%
%      MagickBooleanType DefineImageProperty(Image *image,const char *property,
%        ExceptionInfo *exception)
%
%  A description of each parameter follows:
%
%    o image: the image.
%
%    o property: the image property.
%
%    o exception: return any errors or warnings in this structure.
%
*/
MagickExport MagickBooleanType DefineImageProperty(Image *image,
  const char *property,ExceptionInfo *exception)
{
  char
    key[MagickPathExtent],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -216,7 +216,7 @@
 %
 %  DefineImageProperty() associates an assignment string of the form
 %  "key=value" with an artifact or options. It is equivelent to
-%  SetImageProperty()
+%  SetImageProperty().
 %
 %  The format of the DefineImageProperty method is:
 %
@@ -3975,7 +3975,7 @@
     {
       /*
         Do not 'set' single letter properties - read only shorthand.
-       */
+      */
       (void) ThrowMagickException(exception,GetMagickModule(),OptionError,
         "SetReadOnlyProperty","`%s'",property);
       return(MagickFalse);
```
