# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 113_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `113_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-12 of the vulnerable file.

#include "clar_libgit2.h"

#include "delta.h"

void test_delta_apply__read_at_off(void)
{
	unsigned char base[16] = { 0 }, delta[] = { 0x10, 0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0x10, 0x00, 0x00 };
	void *out;
	size_t outlen;

	cl_git_fail(git_delta_apply(&out, &outlen, base, sizeof(base), delta, sizeof(delta)));
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,3 +10,12 @@
 
 	cl_git_fail(git_delta_apply(&out, &outlen, base, sizeof(base), delta, sizeof(delta)));
 }
+
+void test_delta_apply__read_after_limit(void)
+{
+	unsigned char base[16] = { 0 }, delta[] = { 0x10, 0x70, 0xff };
+	void *out;
+	size_t outlen;
+
+	cl_git_fail(git_delta_apply(&out, &outlen, base, sizeof(base), delta, sizeof(delta)));
+}
```
