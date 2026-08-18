# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 766_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `766_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1529-1569 of the vulnerable file.

%                                                                             %
%                                                                             %
%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
%  LocaleLowercase() convert to lowercase.
%
%  The format of the LocaleLowercase method is:
%
%      void LocaleLowercase(const int c)
%
%  A description of each parameter follows:
%
%    o If c is a uppercase letter, return its lowercase equivalent.
%
*/
MagickExport int LocaleLowercase(const int c)
{
#if defined(MAGICKCORE_LOCALE_SUPPORT)
  if (c_locale != (locale_t) NULL)
    return(tolower_l(c,c_locale));
#endif
  return(tolower(c));
}


/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%                                                                             %
%                                                                             %
%                                                                             %
%   L o c a l e N C o m p a r e                                               %
%                                                                             %
%                                                                             %
%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
%  LocaleNCompare() performs a case-insensitive comparison of two strings
%  byte-by-byte, according to the ordering of the current locale encoding.
%
%  LocaleNCompare returns an integer greater than, equal to, or less than 0,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1546,9 +1546,9 @@
 {
 #if defined(MAGICKCORE_LOCALE_SUPPORT)
   if (c_locale != (locale_t) NULL)
-    return(tolower_l(c,c_locale));
-#endif
-  return(tolower(c));
+    return(tolower_l((int) ((unsigned char) c),c_locale));
+#endif
+  return(tolower((int) ((unsigned char) c)));
 }
 
 
@@ -1687,9 +1687,9 @@
 {
 #if defined(MAGICKCORE_LOCALE_SUPPORT)
   if (c_locale != (locale_t) NULL)
-    return(toupper_l(c,c_locale));
-#endif
-  return(toupper(c));
+    return(toupper_l((int) ((unsigned char) c),c_locale));
+#endif
+  return(toupper((int) ((unsigned char) c)));
 }
 
 
```
