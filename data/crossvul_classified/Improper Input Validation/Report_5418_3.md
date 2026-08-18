# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5418_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5418_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 105-145 of the vulnerable file.

* Code.
\******************************************************************************/

/* Perform formatted output to standard error. */
int jas_eprintf(const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vfprintf(stderr, fmt, ap);
	va_end(ap);
	return ret;
}

/* Dump memory to a stream. */
int jas_memdump(FILE *out, void *data, size_t len)
{
	size_t i;
	size_t j;
	uchar *dp;
	dp = data;
	for (i = 0; i < len; i += 16) {
		fprintf(out, "%04zx:", i);
		for (j = 0; j < 16; ++j) {
			if (i + j < len) {
				fprintf(out, " %02x", dp[i + j]);
			}
		}
		fprintf(out, "\n");
	}
	return 0;
}

/******************************************************************************\
* Code.
\******************************************************************************/

void jas_deprecated(const char *s)
{
	static char message[] =
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,7 +122,7 @@
 {
 	size_t i;
 	size_t j;
-	uchar *dp;
+	jas_uchar *dp;
 	dp = data;
 	for (i = 0; i < len; i += 16) {
 		fprintf(out, "%04zx:", i);
```
