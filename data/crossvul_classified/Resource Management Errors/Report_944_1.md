# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 944_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `944_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 4161-4201 of the vulnerable file.

            *index_image;

          ssize_t
            index;

          if (IfNormalOp && (IsGeometry(arg1) == MagickFalse))
            CLIWandExceptArgBreak(OptionError,"InvalidArgument",option,arg1);
          index=0;
          insert_image=RemoveLastImageFromList(&_images);
          if (IfNormalOp)
            index=(ssize_t) StringToLong(arg1);
          index_image=insert_image;
          if (index == 0)
            PrependImageToList(&_images,insert_image);
          else if (index == (ssize_t) GetImageListLength(_images))
            AppendImageToList(&_images,insert_image);
          else
            {
               index_image=GetImageFromList(_images,index-1);
               if (index_image == (Image *) NULL)
                 CLIWandExceptArgBreak(OptionError,"NoSuchImage",option,arg1);
              InsertImageInList(&index_image,insert_image);
            }
          _images=GetFirstImageInList(index_image);
          break;
        }
      CLIWandExceptionBreak(OptionError,"UnrecognizedOption",option);
    }
    case 'l':
    {
      if (LocaleCompare("layers",option+1) == 0)
        {
          parse=ParseCommandOption(MagickLayerOptions,MagickFalse,arg1);
          if ( parse < 0 )
            CLIWandExceptArgBreak(OptionError,"UnrecognizedLayerMethod",
                 option,arg1);
          switch ((LayerMethod) parse)
          {
            case CoalesceLayer:
            {
              new_images=CoalesceImages(_images,_exception);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4178,7 +4178,10 @@
             {
                index_image=GetImageFromList(_images,index-1);
                if (index_image == (Image *) NULL)
-                 CLIWandExceptArgBreak(OptionError,"NoSuchImage",option,arg1);
+                 {
+                   insert_image=DestroyImage(insert_image);
+                   CLIWandExceptArgBreak(OptionError,"NoSuchImage",option,arg1);
+                 }
               InsertImageInList(&index_image,insert_image);
             }
           _images=GetFirstImageInList(index_image);
```
