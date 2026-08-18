# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 111_2
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `111_2`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1-26 of the vulnerable file.

#include "clar_libgit2.h"

#include "git2/sys/diff.h"

#include "buffer.h"
#include "filebuf.h"
#include "repository.h"

static git_repository *repo;

void test_diff_binary__initialize(void)
{
}

void test_diff_binary__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_patch(
	const char *one,
	const char *two,
	const git_diff_options *opts,
	const char *expected)
{
	git_oid id_one, id_two;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,7 @@
 #include "git2/sys/diff.h"
 
 #include "buffer.h"
+#include "delta.h"
 #include "filebuf.h"
 #include "repository.h"
 
```
