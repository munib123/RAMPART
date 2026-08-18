# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2794_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2794_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 253-278 of the vulnerable file.


#define ASSERT(expr)	\
	(likely(expr) ? (void)0 : asswarn(#expr, __FILE__, __LINE__))

#ifndef STATIC
# define STATIC static noinline
#endif

#else	/* !DEBUG && !XFS_WARN */

#define ASSERT(expr)	((void)0)

#ifndef STATIC
# define STATIC static noinline
#endif

#endif /* XFS_WARN */
#endif /* DEBUG */

#ifdef CONFIG_XFS_RT
#define XFS_IS_REALTIME_INODE(ip) ((ip)->i_d.di_flags & XFS_DIFLAG_REALTIME)
#else
#define XFS_IS_REALTIME_INODE(ip) (0)
#endif

#endif /* __XFS_LINUX__ */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -270,7 +270,14 @@
 #endif /* DEBUG */
 
 #ifdef CONFIG_XFS_RT
-#define XFS_IS_REALTIME_INODE(ip) ((ip)->i_d.di_flags & XFS_DIFLAG_REALTIME)
+
+/*
+ * make sure we ignore the inode flag if the filesystem doesn't have a
+ * configured realtime device.
+ */
+#define XFS_IS_REALTIME_INODE(ip)			\
+	(((ip)->i_d.di_flags & XFS_DIFLAG_REALTIME) &&	\
+	 (ip)->i_mount->m_rtdev_targp)
 #else
 #define XFS_IS_REALTIME_INODE(ip) (0)
 #endif
```
