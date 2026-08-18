# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 4911_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4911_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 236-276 of the vulnerable file.


/* {{{ php_escape_shell_cmd
   Escape all chars that could possibly be used to
   break out of a shell command

   This function emalloc's a string and returns the pointer.
   Remember to efree it when done with it.

   *NOT* safe for binary strings
*/
PHPAPI zend_string *php_escape_shell_cmd(char *str)
{
	register int x, y, l = (int)strlen(str);
	size_t estimate = (2 * l) + 1;
	zend_string *cmd;
#ifndef PHP_WIN32
	char *p = NULL;
#endif


	cmd = zend_string_alloc(2 * l, 0);

	for (x = 0, y = 0; x < l; x++) {
		int mb_len = php_mblen(str + x, (l - x));

		/* skip non-valid multibyte characters */
		if (mb_len < 0) {
			continue;
		} else if (mb_len > 1) {
			memcpy(ZSTR_VAL(cmd) + y, str + x, mb_len);
			y += mb_len;
			x += mb_len - 1;
			continue;
		}

		switch (str[x]) {
#ifndef PHP_WIN32
			case '"':
			case '\'':
				if (!p && (p = memchr(str + x + 1, str[x], l - x - 1))) {
					/* noop */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -253,7 +253,7 @@
 #endif
 
 
-	cmd = zend_string_alloc(2 * l, 0);
+	cmd = zend_string_safe_alloc(2, l, 0, 0);
 
 	for (x = 0, y = 0; x < l; x++) {
 		int mb_len = php_mblen(str + x, (l - x));
@@ -345,7 +345,7 @@
 	size_t estimate = (4 * l) + 3;
 
 
-	cmd = zend_string_alloc(4 * l + 2, 0); /* worst case */
+	cmd = zend_string_safe_alloc(4, l, 2, 0); /* worst case */
 
 #ifdef PHP_WIN32
 	ZSTR_VAL(cmd)[y++] = '"';
```
