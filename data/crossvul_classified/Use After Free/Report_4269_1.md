# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4269_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4269_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 95-118 of the vulnerable file.

   use it.

   Use STRING_GROW () to append what has just been matched, and
   STRING_FINISH () to end the string (it puts the ending 0).
   STRING_FINISH () also stores this string in LAST_STRING, which can be
   used, and which is used by STRING_FREE () to free the last string.  */

#ifndef FLEX_NO_OBSTACK

static struct obstack obstack_for_string;

# define STRING_GROW()                                  \
  obstack_grow (&obstack_for_string, yytext, yyleng)

# define STRING_FINISH()                                \
  (last_string = obstack_finish0 (&obstack_for_string))

# define STRING_1GROW(Char)                     \
  obstack_1grow (&obstack_for_string, Char)

# define STRING_FREE()                                  \
  obstack_free (&obstack_for_string, last_string)

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -112,7 +112,15 @@
 # define STRING_1GROW(Char)                     \
   obstack_1grow (&obstack_for_string, Char)
 
-# define STRING_FREE()                                  \
+# ifdef NDEBUG
+#  define STRING_FREE()                                 \
   obstack_free (&obstack_for_string, last_string)
+# else
+#  define STRING_FREE()                                  \
+  do {                                                   \
+    obstack_free (&obstack_for_string, last_string);     \
+    last_string = NULL;                                  \
+  } while (0)
+#endif
 
 #endif
```
