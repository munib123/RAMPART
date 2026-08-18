# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 1520_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1520_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 632-672 of the vulnerable file.

/* Default: Do not try to guard against extracts redirected by symlinks. */
/* Note: With ARCHIVE_EXTRACT_UNLINK, will remove any intermediate symlink. */
#define	ARCHIVE_EXTRACT_SECURE_SYMLINKS		(0x0100)
/* Default: Do not reject entries with '..' as path elements. */
#define	ARCHIVE_EXTRACT_SECURE_NODOTDOT		(0x0200)
/* Default: Create parent directories as needed. */
#define	ARCHIVE_EXTRACT_NO_AUTODIR		(0x0400)
/* Default: Overwrite files, even if one on disk is newer. */
#define	ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER	(0x0800)
/* Detect blocks of 0 and write holes instead. */
#define	ARCHIVE_EXTRACT_SPARSE			(0x1000)
/* Default: Do not restore Mac extended metadata. */
/* This has no effect except on Mac OS. */
#define	ARCHIVE_EXTRACT_MAC_METADATA		(0x2000)
/* Default: Use HFS+ compression if it was compressed. */
/* This has no effect except on Mac OS v10.6 or later. */
#define	ARCHIVE_EXTRACT_NO_HFS_COMPRESSION	(0x4000)
/* Default: Do not use HFS+ compression if it was not compressed. */
/* This has no effect except on Mac OS v10.6 or later. */
#define	ARCHIVE_EXTRACT_HFS_COMPRESSION_FORCED	(0x8000)

__LA_DECL int archive_read_extract(struct archive *, struct archive_entry *,
		     int flags);
__LA_DECL int archive_read_extract2(struct archive *, struct archive_entry *,
		     struct archive * /* dest */);
__LA_DECL void	 archive_read_extract_set_progress_callback(struct archive *,
		     void (*_progress_func)(void *), void *_user_data);

/* Record the dev/ino of a file that will not be written.  This is
 * generally set to the dev/ino of the archive being read. */
__LA_DECL void		archive_read_extract_set_skip_file(struct archive *,
		     __LA_INT64_T, __LA_INT64_T);

/* Close the file and release most resources. */
__LA_DECL int		 archive_read_close(struct archive *);
/* Release all resources and destroy the object. */
/* Note that archive_read_free will call archive_read_close for you. */
__LA_DECL int		 archive_read_free(struct archive *);
#if ARCHIVE_VERSION_NUMBER < 4000000
/* Synonym for archive_read_free() for backwards compatibility. */
__LA_DECL int		 archive_read_finish(struct archive *) __LA_DEPRECATED;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -649,6 +649,8 @@
 /* Default: Do not use HFS+ compression if it was not compressed. */
 /* This has no effect except on Mac OS v10.6 or later. */
 #define	ARCHIVE_EXTRACT_HFS_COMPRESSION_FORCED	(0x8000)
+/* Default: Do not reject entries with absolute paths */
+#define ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS (0x10000)
 
 __LA_DECL int archive_read_extract(struct archive *, struct archive_entry *,
 		     int flags);
```
