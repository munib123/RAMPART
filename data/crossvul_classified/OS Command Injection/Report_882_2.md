# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in c
**Pair ID:** 882_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `882_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```c
Lines 750-790 of the vulnerable file.

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
    1364,
/**/
    1363,
/**/
    1362,
/**/
    1361,
/**/
    1360,
/**/
    1359,
/**/
    1358,
/**/
    1357,
/**/
    1356,
/**/
    1355,
/**/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -767,6 +767,8 @@
 
 static int included_patches[] =
 {   /* Add new patch number below this line */
+/**/
+    1365,
 /**/
     1364,
 /**/
```
