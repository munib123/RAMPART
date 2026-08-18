# CrossVul Fix Pair: Improper Check for Dropped Privileges in c
**Pair ID:** 1198_2
**Vulnerability Class:** Improper Check for Dropped Privileges
**CWE:** CWE-273
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1198_2`)

## Vulnerability Information & PoC

## Description
Improper Check for Dropped Privileges - If the drop fails, the product will continue to run with the raised privileges, which might provide additional access to unprivileged users.

## Vulnerable Code
```c
Lines 3829-3888 of the vulnerable file.

}

static int
bash_complete_variable_internal (what_to_do)
     int what_to_do;
{
  return bash_specific_completion (what_to_do, variable_completion_function);
}

static int
bash_complete_command_internal (what_to_do)
     int what_to_do;
{
  return bash_specific_completion (what_to_do, command_word_completion_function);
}

static int
completion_glob_pattern (string)
     char *string;
{
  register int c;
  char *send;
  int open;

  DECLARE_MBSTATE;

  open = 0;
  send = string + strlen (string);

  while (c = *string++)
    {
      switch (c)
	{
	case '?':
	case '*':
	  return (1);

	case '[':
	  open++;
	  continue;

	case ']':
	  if (open)
	    return (1);
	  continue;

	case '+':
	case '@':
	case '!':
	  if (*string == '(')	/*)*/
	    return (1);
	  continue;

	case '\\':
	  if (*string++ == 0)
	    return (0);
	}

      /* Advance one fewer byte than an entire multibyte character to
	 account for the auto-increment in the loop above. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3846,55 +3846,7 @@
 completion_glob_pattern (string)
      char *string;
 {
-  register int c;
-  char *send;
-  int open;
-
-  DECLARE_MBSTATE;
-
-  open = 0;
-  send = string + strlen (string);
-
-  while (c = *string++)
-    {
-      switch (c)
-	{
-	case '?':
-	case '*':
-	  return (1);
-
-	case '[':
-	  open++;
-	  continue;
-
-	case ']':
-	  if (open)
-	    return (1);
-	  continue;
-
-	case '+':
-	case '@':
-	case '!':
-	  if (*string == '(')	/*)*/
-	    return (1);
-	  continue;
-
-	case '\\':
-	  if (*string++ == 0)
-	    return (0);
-	}
-
-      /* Advance one fewer byte than an entire multibyte character to
-	 account for the auto-increment in the loop above. */
-#ifdef HANDLE_MULTIBYTE
-      string--;
-      ADVANCE_CHAR_P (string, send - string);
-      string++;
-#else
-      ADVANCE_CHAR_P (string, send - string);
-#endif
-    }
-  return (0);
+  return (glob_pattern_p (string) == 1);
 }
 
 static char *globtext;
```
