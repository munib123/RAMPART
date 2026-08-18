# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 4773_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4773_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 2144-2184 of the vulnerable file.

                (void) ThrowMagickException(exception,GetMagickModule(),
                  OptionWarning,"ParseError","missing >");
                utf8=DestroyString(utf8);
                return(&root->root);
              }
            if ((ignore_depth == 0) && (IsSkipTag(tag) == MagickFalse))
              {
                ParseOpenTag(root,tag,attributes);
                (void) ParseCloseTag(root,tag,exception);
              }
          }
        else
          {
            c=(*p);
            if ((*p == '>') || ((*p == '\0') && (terminal == '>')))
              {
                *p='\0';
                if ((ignore_depth == 0) && (IsSkipTag(tag) == MagickFalse))
                  ParseOpenTag(root,tag,attributes);
                else
                  ignore_depth++;
                *p=c;
              }
            else
              {
                if (l != 0)
                  (void) DestroyXMLTreeAttributes(attributes);
                (void) ThrowMagickException(exception,GetMagickModule(),
                  OptionWarning,"ParseError","missing >");
                utf8=DestroyString(utf8);
                return(&root->root);
              }
          }
      }
    else
      if (*p == '/')
        {
          /*
            Close tag.
          */
          tag=p+1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2161,7 +2161,10 @@
                 if ((ignore_depth == 0) && (IsSkipTag(tag) == MagickFalse))
                   ParseOpenTag(root,tag,attributes);
                 else
-                  ignore_depth++;
+                  {
+                    ignore_depth++;
+                    (void) DestroyXMLTreeAttributes(attributes);
+                  }
                 *p=c;
               }
             else
```
