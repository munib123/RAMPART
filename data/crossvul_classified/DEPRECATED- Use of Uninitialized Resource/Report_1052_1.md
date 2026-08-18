# CrossVul Fix Pair: DEPRECATED: Use of Uninitialized Resource in c
**Pair ID:** 1052_1
**Vulnerability Class:** DEPRECATED- Use of Uninitialized Resource
**CWE:** CWE-1187
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1052_1`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Use of Uninitialized Resource - This entry has been deprecated because it was a duplicate of CWE-908.

## Vulnerable Code
```c
Lines 68-108 of the vulnerable file.

usage(void)
{
	fprintf(stderr, "usage: doas [-ns] [-a style] [-C config] [-u user]"
	    " command [args]\n");
	exit(1);
}

#ifdef linux
void
errc(int eval, int code, const char *format)
{
   fprintf(stderr, "%s", format);
   exit(code);
}
#endif

static int
parseuid(const char *s, uid_t *uid)
{
	struct passwd *pw;
	const char *errstr;

	if ((pw = getpwnam(s)) != NULL) {
		*uid = pw->pw_uid;
		return 0;
	}
	#if !defined(__linux__) && !defined(__NetBSD__)
	*uid = strtonum(s, 0, UID_MAX, &errstr);
	#else
	sscanf(s, "%d", uid);
	#endif
	if (errstr)
		return -1;
	return 0;
}

static int
uidcheck(const char *s, uid_t desired)
{
	uid_t uid;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,7 +85,11 @@
 parseuid(const char *s, uid_t *uid)
 {
 	struct passwd *pw;
-	const char *errstr;
+	#if !defined(__linux__) && !defined(__NetBSD__)
+	const char *errstr = NULL;
+        #else
+        int status;
+        #endif
 
 	if ((pw = getpwnam(s)) != NULL) {
 		*uid = pw->pw_uid;
@@ -93,11 +97,13 @@
 	}
 	#if !defined(__linux__) && !defined(__NetBSD__)
 	*uid = strtonum(s, 0, UID_MAX, &errstr);
-	#else
-	sscanf(s, "%d", uid);
-	#endif
 	if (errstr)
 		return -1;
+	#else
+	status = sscanf(s, "%d", uid);
+        if (status != 1)
+           return -1;
+	#endif
 	return 0;
 }
 
@@ -117,7 +123,11 @@
 parsegid(const char *s, gid_t *gid)
 {
 	struct group *gr;
-	const char *errstr;
+	#if !defined(__linux__) && !defined(__NetBSD__)
+	const char *errstr = NULL;
+        #else
+        int status;
+        #endif
 
 	if ((gr = getgrnam(s)) != NULL) {
 		*gid = gr->gr_gid;
@@ -125,11 +135,13 @@
 	}
 	#if !defined(__linux__) && !defined(__NetBSD__)
 	*gid = strtonum(s, 0, GID_MAX, &errstr);
-	#else
-	sscanf(s, "%d", gid);
-	#endif
 	if (errstr)
 		return -1;
+	#else
+	status = sscanf(s, "%d", gid);
+        if (status != 1)
+            return -1;
+	#endif
 	return 0;
 }
 
```
