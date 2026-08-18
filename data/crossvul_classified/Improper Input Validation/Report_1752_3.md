# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1752_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1752_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1-23 of the vulnerable file.

#define RUBY_VERSION "2.1.8"
#define RUBY_RELEASE_DATE "2015-12-16"
#define RUBY_PATCHLEVEL 438

#define RUBY_RELEASE_YEAR 2015
#define RUBY_RELEASE_MONTH 12
#define RUBY_RELEASE_DAY 16

#include "ruby/version.h"

#if !defined RUBY_LIB_VERSION && defined RUBY_LIB_VERSION_STYLE
# if RUBY_LIB_VERSION_STYLE == 3
#   define RUBY_LIB_VERSION STRINGIZE(RUBY_API_VERSION_MAJOR)"."STRINGIZE(RUBY_API_VERSION_MINOR)"."STRINGIZE(RUBY_API_VERSION_TEENY)
# elif RUBY_LIB_VERSION_STYLE == 2
#   define RUBY_LIB_VERSION STRINGIZE(RUBY_API_VERSION_MAJOR)"."STRINGIZE(RUBY_API_VERSION_MINOR)
# endif
#endif

#if RUBY_PATCHLEVEL == -1
#define RUBY_PATCHLEVEL_STR "dev"
#else
#define RUBY_PATCHLEVEL_STR "p"STRINGIZE(RUBY_PATCHLEVEL)
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 #define RUBY_VERSION "2.1.8"
 #define RUBY_RELEASE_DATE "2015-12-16"
-#define RUBY_PATCHLEVEL 438
+#define RUBY_PATCHLEVEL 439
 
 #define RUBY_RELEASE_YEAR 2015
 #define RUBY_RELEASE_MONTH 12
```
