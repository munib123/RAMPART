# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4789_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4789_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 4988-5028 of the vulnerable file.

        }
      if (LocaleCompare((const char *) tag,"read") == 0)
        {
          if (attributes == (const xmlChar **) NULL)
            break;
          for (i=0; (attributes[i] != (const xmlChar *) NULL); i++)
          {
            keyword=(const char *) attributes[i++];
            CloneString(&value,InterpretImageProperties(msl_info->image_info[n],
              msl_info->attributes[n],(const char *) attributes[i]));
            switch (*keyword)
            {
              case 'F':
              case 'f':
              {
                if (LocaleCompare(keyword,"filename") == 0)
                  {
                    Image
                      *image;

                    (void) CopyMagickString(msl_info->image_info[n]->filename,
                      value,MaxTextExtent);
                    image=ReadImage(msl_info->image_info[n],exception);
                    CatchException(exception);
                    if (image == (Image *) NULL)
                      continue;
                    AppendImageToList(&msl_info->image[n],image);
                    break;
                  }
                (void) SetMSLAttributes(msl_info,keyword,value);
                break;
              }
              default:
              {
                (void) SetMSLAttributes(msl_info,keyword,value);
                break;
              }
            }
          }
          break;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5005,6 +5005,8 @@
                     Image
                       *image;
 
+                    if (value == (char *) NULL)
+                      break;
                     (void) CopyMagickString(msl_info->image_info[n]->filename,
                       value,MaxTextExtent);
                     image=ReadImage(msl_info->image_info[n],exception);
```
