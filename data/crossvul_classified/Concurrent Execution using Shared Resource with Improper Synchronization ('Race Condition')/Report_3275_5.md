# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3275_5
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3275_5`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 276-327 of the vulnerable file.

	/* both times implies a utime(s) call */
	if ((ia_valid & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME))
		mask |= FS_ATTRIB;
	else if (ia_valid & ATTR_ATIME)
		mask |= FS_ACCESS;
	else if (ia_valid & ATTR_MTIME)
		mask |= FS_MODIFY;

	if (ia_valid & ATTR_MODE)
		mask |= FS_ATTRIB;

	if (mask) {
		if (S_ISDIR(inode->i_mode))
			mask |= FS_ISDIR;

		fsnotify_parent(NULL, dentry, mask);
		fsnotify(inode, mask, inode, FSNOTIFY_EVENT_INODE, NULL, 0);
	}
}

#if defined(CONFIG_FSNOTIFY)	/* notify helpers */

/*
 * fsnotify_oldname_init - save off the old filename before we change it
 */
static inline const unsigned char *fsnotify_oldname_init(const unsigned char *name)
{
	return kstrdup(name, GFP_KERNEL);
}

/*
 * fsnotify_oldname_free - free the name we got from fsnotify_oldname_init
 */
static inline void fsnotify_oldname_free(const unsigned char *old_name)
{
	kfree(old_name);
}

#else	/* CONFIG_FSNOTIFY */

static inline const char *fsnotify_oldname_init(const unsigned char *name)
{
	return NULL;
}

static inline void fsnotify_oldname_free(const unsigned char *old_name)
{
}

#endif	/*  CONFIG_FSNOTIFY */

#endif	/* _LINUX_FS_NOTIFY_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -293,35 +293,4 @@
 	}
 }
 
-#if defined(CONFIG_FSNOTIFY)	/* notify helpers */
-
-/*
- * fsnotify_oldname_init - save off the old filename before we change it
- */
-static inline const unsigned char *fsnotify_oldname_init(const unsigned char *name)
-{
-	return kstrdup(name, GFP_KERNEL);
-}
-
-/*
- * fsnotify_oldname_free - free the name we got from fsnotify_oldname_init
- */
-static inline void fsnotify_oldname_free(const unsigned char *old_name)
-{
-	kfree(old_name);
-}
-
-#else	/* CONFIG_FSNOTIFY */
-
-static inline const char *fsnotify_oldname_init(const unsigned char *name)
-{
-	return NULL;
-}
-
-static inline void fsnotify_oldname_free(const unsigned char *old_name)
-{
-}
-
-#endif	/*  CONFIG_FSNOTIFY */
-
 #endif	/* _LINUX_FS_NOTIFY_H */
```
