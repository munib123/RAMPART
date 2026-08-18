# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3989_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3989_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 189-229 of the vulnerable file.

#ifdef GIT_WIN32
	test_checkout_fails("refs/heads/dot_backslash_dotcapitalgit_path", ".GIT/foobar");
#endif
}

/* A tree that contains an entry ".git.", because Win32 APIs will drop the
 * trailing slash.
 */
void test_checkout_nasty__dot_git_dot(void)
{
#ifdef GIT_WIN32
	test_checkout_fails("refs/heads/dot_git_dot", ".git/foobar");
#endif
}

/* A tree that contains an entry "git~1", because that is typically the
 * short name for ".git".
 */
void test_checkout_nasty__git_tilde1(void)
{
#ifdef GIT_WIN32
	test_checkout_fails("refs/heads/git_tilde1", ".git/foobar");
#endif
}

/* A tree that contains an entry "git~2", when we have forced the short
 * name for ".git" into "GIT~2".
 */
void test_checkout_nasty__git_custom_shortname(void)
{
#ifdef GIT_WIN32
	if (!cl_sandbox_supports_8dot3())
		clar__skip();

	cl_must_pass(p_rename("nasty/.git", "nasty/_temp"));
	cl_git_write2file("nasty/git~1", "", 0, O_RDWR|O_CREAT, 0666);
	cl_must_pass(p_rename("nasty/_temp", "nasty/.git"));
	test_checkout_fails("refs/heads/git_tilde2", ".git/foobar");
#endif
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -206,9 +206,8 @@
  */
 void test_checkout_nasty__git_tilde1(void)
 {
-#ifdef GIT_WIN32
 	test_checkout_fails("refs/heads/git_tilde1", ".git/foobar");
-#endif
+	test_checkout_fails("refs/heads/git_tilde1", "git~1/foobar");
 }
 
 /* A tree that contains an entry "git~2", when we have forced the short
```
