# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4493_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4493_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2712-2752 of the vulnerable file.

		{
			self->OutStream(self, ch);
		}
	}
	else
	{
		self->OutStream(self, ch);
	}
}

/*************************************************************************
 * TrioWriteString
 *
 * Description:
 *  Output a string
 */
TRIO_PRIVATE void TrioWriteString TRIO_ARGS5((self, string, flags, width, precision),
                                             trio_class_t* self, TRIO_CONST char* string,
                                             trio_flags_t flags, int width, int precision)
{
	int length;
	int ch;

	assert(VALID(self));
	assert(VALID(self->OutStream));

	if (string == NULL)
	{
		string = internalNullString;
		length = sizeof(internalNullString) - 1;
#if TRIO_FEATURE_QUOTE
		/* Disable quoting for the null pointer */
		flags &= (~FLAGS_QUOTE);
#endif
		width = 0;
	}
	else
	{
		if (precision == 0)
		{
			length = trio_length(string);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2729,7 +2729,7 @@
                                              trio_class_t* self, TRIO_CONST char* string,
                                              trio_flags_t flags, int width, int precision)
 {
-	int length;
+	int length = 0;
 	int ch;
 
 	assert(VALID(self));
@@ -2747,7 +2747,7 @@
 	}
 	else
 	{
-		if (precision == 0)
+		if (precision <= 0)
 		{
 			length = trio_length(string);
 		}
@@ -4754,7 +4754,7 @@
 		}
 
 		/* Bail out if namespace is too long */
-		if (trio_length(name) >= MAX_USER_NAME)
+		if (trio_length_max(name, MAX_USER_NAME) >= MAX_USER_NAME)
 			return NULL;
 
 		/* Bail out if namespace already is registered */
```
