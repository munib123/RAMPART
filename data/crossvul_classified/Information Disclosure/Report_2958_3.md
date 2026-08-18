# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2958_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2958_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 744-784 of the vulnerable file.

#  else
	"-xsmp",
#  endif
# endif
# ifdef FEAT_XCLIPBOARD
	"+xterm_clipboard",
# else
	"-xterm_clipboard",
# endif
#endif
#ifdef FEAT_XTERM_SAVE
	"+xterm_save",
#else
	"-xterm_save",
#endif
	NULL
};

static int included_patches[] =
{   /* Add new patch number below this line */
/**/
    1262,
/**/
    1261,
/**/
    1260,
/**/
    1259,
/**/
    1258,
/**/
    1257,
/**/
    1256,
/**/
    1255,
/**/
    1254,
/**/
    1253,
/**/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -761,6 +761,8 @@
 
 static int included_patches[] =
 {   /* Add new patch number below this line */
+/**/
+    1263,
 /**/
     1262,
 /**/
```
