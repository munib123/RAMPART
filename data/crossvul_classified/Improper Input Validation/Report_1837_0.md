# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1837_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1837_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 261-301 of the vulnerable file.

          p=keyword;
          do
          {
            if ((size_t) (p-keyword) < (MaxTextExtent-1))
              *p++=c;
            c=ReadBlobByte(image);
          } while (isalnum(c) || (c == '_'));
          *p='\0';
          value_expected=MagickFalse;
          while ((isspace((int) ((unsigned char) c)) != 0) || (c == '='))
          {
            if (c == '=')
              value_expected=MagickTrue;
            c=ReadBlobByte(image);
          }
          if (LocaleCompare(keyword,"Y") == 0)
            value_expected=MagickTrue;
          if (value_expected == MagickFalse)
            continue;
          p=value;
          while ((c != '\n') && (c != '\0'))
          {
            if ((size_t) (p-value) < (MaxTextExtent-1))
              *p++=c;
            c=ReadBlobByte(image);
          }
          *p='\0';
          /*
            Assign a value to the specified keyword.
          */
          switch (*keyword)
          {
            case 'F':
            case 'f':
            {
              if (LocaleCompare(keyword,"format") == 0)
                {
                  (void) CopyMagickString(format,value,MaxTextExtent);
                  break;
                }
              (void) FormatLocaleString(tag,MaxTextExtent,"hdr:%s",keyword);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -278,7 +278,7 @@
           if (value_expected == MagickFalse)
             continue;
           p=value;
-          while ((c != '\n') && (c != '\0'))
+          while ((c != '\n') && (c != '\0') && (c != EOF))
           {
             if ((size_t) (p-value) < (MaxTextExtent-1))
               *p++=c;
@@ -323,18 +323,20 @@
                     chromaticity[6],
                     white_point[2];
 
-                  (void) sscanf(value,"%g %g %g %g %g %g %g %g",
-                    &chromaticity[0],&chromaticity[1],&chromaticity[2],
-                    &chromaticity[3],&chromaticity[4],&chromaticity[5],
-                    &white_point[0],&white_point[1]);
-                  image->chromaticity.red_primary.x=chromaticity[0];
-                  image->chromaticity.red_primary.y=chromaticity[1];
-                  image->chromaticity.green_primary.x=chromaticity[2];
-                  image->chromaticity.green_primary.y=chromaticity[3];
-                  image->chromaticity.blue_primary.x=chromaticity[4];
-                  image->chromaticity.blue_primary.y=chromaticity[5];
-                  image->chromaticity.white_point.x=white_point[0],
-                  image->chromaticity.white_point.y=white_point[1];
+                  if (sscanf(value,"%g %g %g %g %g %g %g %g",&chromaticity[0],
+                      &chromaticity[1],&chromaticity[2],&chromaticity[3],
+                      &chromaticity[4],&chromaticity[5],&white_point[0],
+                      &white_point[1]) == 8)
+                    {
+                      image->chromaticity.red_primary.x=chromaticity[0];
+                      image->chromaticity.red_primary.y=chromaticity[1];
+                      image->chromaticity.green_primary.x=chromaticity[2];
+                      image->chromaticity.green_primary.y=chromaticity[3];
+                      image->chromaticity.blue_primary.x=chromaticity[4];
+                      image->chromaticity.blue_primary.y=chromaticity[5];
+                      image->chromaticity.white_point.x=white_point[0],
+                      image->chromaticity.white_point.y=white_point[1];
+                    }
                   break;
                 }
               (void) FormatLocaleString(tag,MaxTextExtent,"hdr:%s",keyword);
@@ -353,9 +355,11 @@
                     height,
                     width;
 
-                  (void) sscanf(value,"%d +X %d",&height,&width);
-                  image->columns=(size_t) width;
-                  image->rows=(size_t) height;
+                  if (sscanf(value,"%d +X %d",&height,&width) == 2)
+                    {
+                      image->columns=(size_t) width;
+                      image->rows=(size_t) height;
+                    }
                   break;
                 }
               (void) FormatLocaleString(tag,MaxTextExtent,"hdr:%s",keyword);
```
