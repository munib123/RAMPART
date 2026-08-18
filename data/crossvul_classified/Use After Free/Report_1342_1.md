# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1342_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1342_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 736-776 of the vulnerable file.

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
    2135,
/**/
    2134,
/**/
    2133,
/**/
    2132,
/**/
    2131,
/**/
    2130,
/**/
    2129,
/**/
    2128,
/**/
    2127,
/**/
    2126,
/**/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -753,6 +753,8 @@
 
 static int included_patches[] =
 {   /* Add new patch number below this line */
+/**/
+    2136,
 /**/
     2135,
 /**/
```
