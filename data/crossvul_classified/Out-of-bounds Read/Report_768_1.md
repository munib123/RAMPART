# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 768_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `768_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1527-1567 of the vulnerable file.

%                                                                             %
%   L o c a l e L o w e r c a s e                                             %
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
    return(tolower_l((int) ((unsigned char) c),c_locale));
#endif
  return(tolower((int) ((unsigned char) c)));
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1544,6 +1544,8 @@
 */
 MagickExport int LocaleLowercase(const int c)
 {
+  if (c < 0)
+    return(c);
 #if defined(MAGICKCORE_LOCALE_SUPPORT)
   if (c_locale != (locale_t) NULL)
     return(tolower_l((int) ((unsigned char) c),c_locale));
@@ -1685,6 +1687,8 @@
 */
 MagickExport int LocaleUppercase(const int c)
 {
+  if (c < 0)
+    return(c);
 #if defined(MAGICKCORE_LOCALE_SUPPORT)
   if (c_locale != (locale_t) NULL)
     return(toupper_l((int) ((unsigned char) c),c_locale));
```
