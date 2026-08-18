# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3987_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3987_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 256-296 of the vulnerable file.

/* A tree that contains an entry "git:", because Win32 APIs will reject
 * that as looking too similar to a drive letter.
 */
void test_checkout_nasty__dot_git_colon(void)
{
#ifdef GIT_WIN32
	test_checkout_fails("refs/heads/dot_git_colon", ".git/foobar");
#endif
}

/* A tree that contains an entry "git:foo", because Win32 APIs will turn
 * that into ".git".
 */
void test_checkout_nasty__dot_git_colon_stuff(void)
{
#ifdef GIT_WIN32
	test_checkout_fails("refs/heads/dot_git_colon_stuff", ".git/foobar");
#endif
}

/* Trees that contains entries with a tree ".git" that contain
 * byte sequences:
 * { 0xe2, 0x80, 0x8c }
 * { 0xe2, 0x80, 0x8d }
 * { 0xe2, 0x80, 0x8e }
 * { 0xe2, 0x80, 0x8f }
 * { 0xe2, 0x80, 0xaa }
 * { 0xe2, 0x80, 0xab }
 * { 0xe2, 0x80, 0xac }
 * { 0xe2, 0x80, 0xad }
 * { 0xe2, 0x81, 0xae }
 * { 0xe2, 0x81, 0xaa }
 * { 0xe2, 0x81, 0xab }
 * { 0xe2, 0x81, 0xac }
 * { 0xe2, 0x81, 0xad }
 * { 0xe2, 0x81, 0xae }
 * { 0xe2, 0x81, 0xaf }
 * { 0xef, 0xbb, 0xbf }
 * Because these map to characters that HFS filesystems "ignore".  Thus
 * ".git<U+200C>" will map to ".git".
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -271,6 +271,16 @@
 #ifdef GIT_WIN32
 	test_checkout_fails("refs/heads/dot_git_colon_stuff", ".git/foobar");
 #endif
+}
+
+/* A tree that contains an entry ".git::$INDEX_ALLOCATION" because NTFS
+ * will interpret that as a synonym to ".git", even when mounted via SMB
+ * on macOS.
+ */
+void test_checkout_nasty__dotgit_alternate_data_stream(void)
+{
+	test_checkout_fails("refs/heads/dotgit_alternate_data_stream", ".git/dummy-file");
+	test_checkout_fails("refs/heads/dotgit_alternate_data_stream", ".git::$INDEX_ALLOCATION/dummy-file");
 }
 
 /* Trees that contains entries with a tree ".git" that contain
```
