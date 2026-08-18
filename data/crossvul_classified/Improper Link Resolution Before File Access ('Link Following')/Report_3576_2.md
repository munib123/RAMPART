# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 3576_2
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3576_2`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 269-309 of the vulnerable file.

/* Function: unescape */
char *unescape(const char *s, int len, const char *extra);

/* Extra characters to be escaped in strings and regexps respectively */
#define STR_ESCAPES "\"\\"
#define RX_ESCAPES  "/\\"

/* Function: print_chars */
int print_chars(FILE *out, const char *text, int cnt);

/* Function: print_pos
 * Print a pretty representation of being at position POS within TEXT */
void print_pos(FILE *out, const char *text, int pos);
char *format_pos(const char *text, int pos);

/* Function: xread_file
 * Read the contents of file PATH and return them as one long string. The
 * caller must free the result. Return NULL if any error occurs.
 */
char* xread_file(const char *path);

/* Get the error message for ERRNUM in a threadsafe way. Based on libvirt's
 * virStrError
 */
const char *xstrerror(int errnum, char *buf, size_t len);

/* Like asprintf, but set *STRP to NULL on error */
int xasprintf(char **strp, const char *format, ...);

/* Convert S to RESULT with error checking */
int xstrtoint64(char const *s, int base, int64_t *result);

/* Calculate line and column number of character POS in TEXT */
void calc_line_ofs(const char *text, size_t pos, size_t *line, size_t *ofs);

/* Cleans path from user, removing trailing slashes and whitespace */
char *cleanpath(char *path);

/* Take the first LEN characters from the regexp *U and expand any
 * character ranges in it. The expanded regexp, if expansion is necessary,
 * is in U, and the old string is freed. If expansion is not needed or an
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -286,6 +286,9 @@
  * caller must free the result. Return NULL if any error occurs.
  */
 char* xread_file(const char *path);
+
+/* Like xread_file, but caller supplies a file pointer */
+char* xfread_file(FILE *fp);
 
 /* Get the error message for ERRNUM in a threadsafe way. Based on libvirt's
  * virStrError
```
