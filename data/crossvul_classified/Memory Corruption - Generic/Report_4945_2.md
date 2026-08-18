# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4945_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4945_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 21-61 of the vulnerable file.

#include "bisect.h"

volatile show_early_output_fn_t show_early_output;

static const char *term_bad;
static const char *term_good;

char *path_name(const struct name_path *path, const char *name)
{
	const struct name_path *p;
	char *n, *m;
	int nlen = strlen(name);
	int len = nlen + 1;

	for (p = path; p; p = p->up) {
		if (p->elem_len)
			len += p->elem_len + 1;
	}
	n = xmalloc(len);
	m = n + len - (nlen + 1);
	strcpy(m, name);
	for (p = path; p; p = p->up) {
		if (p->elem_len) {
			m -= p->elem_len + 1;
			memcpy(m, p->elem, p->elem_len);
			m[p->elem_len] = '/';
		}
	}
	return n;
}

static int show_path_component_truncated(FILE *out, const char *name, int len)
{
	int cnt;
	for (cnt = 0; cnt < len; cnt++) {
		int ch = name[cnt];
		if (!ch || ch == '\n')
			return -1;
		fputc(ch, out);
	}
	return len;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,7 +38,7 @@
 	}
 	n = xmalloc(len);
 	m = n + len - (nlen + 1);
-	strcpy(m, name);
+	memcpy(m, name, nlen + 1);
 	for (p = path; p; p = p->up) {
 		if (p->elem_len) {
 			m -= p->elem_len + 1;
```
