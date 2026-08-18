# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 1520_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1520_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 154-194 of the vulnerable file.


	/* Set lafe_progname before calling lafe_warnc. */
	lafe_setprogname(*argv, "bsdcpio");

#if HAVE_SETLOCALE
	if (setlocale(LC_ALL, "") == NULL)
		lafe_warnc(0, "Failed to set default locale");
#endif

	cpio->uid_override = -1;
	cpio->gid_override = -1;
	cpio->argv = argv;
	cpio->argc = argc;
	cpio->mode = '\0';
	cpio->verbose = 0;
	cpio->compress = '\0';
	cpio->extract_flags = ARCHIVE_EXTRACT_NO_AUTODIR;
	cpio->extract_flags |= ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER;
	cpio->extract_flags |= ARCHIVE_EXTRACT_SECURE_SYMLINKS;
	cpio->extract_flags |= ARCHIVE_EXTRACT_SECURE_NODOTDOT;
	cpio->extract_flags |= ARCHIVE_EXTRACT_PERM;
	cpio->extract_flags |= ARCHIVE_EXTRACT_FFLAGS;
	cpio->extract_flags |= ARCHIVE_EXTRACT_ACL;
#if !defined(_WIN32) && !defined(__CYGWIN__)
	if (geteuid() == 0)
		cpio->extract_flags |= ARCHIVE_EXTRACT_OWNER;
#endif
	cpio->bytes_per_block = 512;
	cpio->filename = NULL;

	cpio->matching = archive_match_new();
	if (cpio->matching == NULL)
		lafe_errc(1, 0, "Out of memory");

	while ((opt = cpio_getopt(cpio)) != -1) {
		switch (opt) {
		case '0': /* GNU convention: --null, -0 */
			cpio->option_null = 1;
			break;
		case 'A': /* NetBSD/OpenBSD */
			cpio->option_append = 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -171,6 +171,7 @@
 	cpio->extract_flags |= ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER;
 	cpio->extract_flags |= ARCHIVE_EXTRACT_SECURE_SYMLINKS;
 	cpio->extract_flags |= ARCHIVE_EXTRACT_SECURE_NODOTDOT;
+	cpio->extract_flags |= ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS;
 	cpio->extract_flags |= ARCHIVE_EXTRACT_PERM;
 	cpio->extract_flags |= ARCHIVE_EXTRACT_FFLAGS;
 	cpio->extract_flags |= ARCHIVE_EXTRACT_ACL;
@@ -256,6 +257,7 @@
 		case OPTION_INSECURE:
 			cpio->extract_flags &= ~ARCHIVE_EXTRACT_SECURE_SYMLINKS;
 			cpio->extract_flags &= ~ARCHIVE_EXTRACT_SECURE_NODOTDOT;
+			cpio->extract_flags &= ~ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS;
 			break;
 		case 'L': /* GNU cpio */
 			cpio->option_follow_links = 1;
```
