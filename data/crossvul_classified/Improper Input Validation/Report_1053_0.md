# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1053_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1053_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 525-565 of the vulnerable file.

			err(1, "dup2");
#endif
#else
#error	No auth module!
#endif
	}

        /*
	if (pledge("stdio rpath getpw exec id", NULL) == -1)
		err(1, "pledge");
        */
	target_pw = getpwuid(target);
	if (! target_pw)
		errx(1, "no passwd entry for target");

#if defined(HAVE_LOGIN_CAP_H)
	if (setusercontext(NULL, target_pw, target, LOGIN_SETGROUP |
	    LOGIN_SETPRIORITY | LOGIN_SETRESOURCES | LOGIN_SETUMASK |
	    LOGIN_SETUSER) != 0)
		errx(1, "failed to set user context for target");
#endif
        /*
	if (pledge("stdio rpath exec", NULL) == -1)
		err(1, "pledge");
        */

	if (getcwd(cwdpath, sizeof(cwdpath)) == NULL)
		cwd = "(failed)";
	else
		cwd = cwdpath;

	/*
        if (pledge("stdio exec", NULL) == -1)
		err(1, "pledge");
        */
#ifndef HAVE_LOGIN_CAP_H
        /* If we effectively are root, set the UID to actually be root to avoid
           permission errors. */
        if (target != 0)
           setuid(target);
        if ( geteuid() == ROOT_UID )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -542,6 +542,23 @@
 	    LOGIN_SETPRIORITY | LOGIN_SETRESOURCES | LOGIN_SETUMASK |
 	    LOGIN_SETUSER) != 0)
 		errx(1, "failed to set user context for target");
+#else
+	#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
+	if (setresgid(target_pw->pw_gid, target_pw->pw_gid, target_pw->pw_gid) == -1)
+		err(1, "setresgid");
+	#else
+	if (setregid(target_pw->pw_gid, target_pw->pw_gid) == -1)
+		err(1, "setregid");
+	#endif
+	if (initgroups(target_pw->pw_name, target_pw->pw_gid) == -1)
+		err(1, "initgroups");
+	#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
+	if (setresuid(target, target, target) == -1)
+		err(1, "setresuid");
+	#else
+	if (setreuid(target, target) == -1)
+		err(1, "setreuid");
+	#endif
 #endif
         /*
 	if (pledge("stdio rpath exec", NULL) == -1)
@@ -557,14 +574,6 @@
         if (pledge("stdio exec", NULL) == -1)
 		err(1, "pledge");
         */
-#ifndef HAVE_LOGIN_CAP_H
-        /* If we effectively are root, set the UID to actually be root to avoid
-           permission errors. */
-        if (target != 0)
-           setuid(target);
-        if ( geteuid() == ROOT_UID )
-           setuid(ROOT_UID);
-#endif
 
 	syslog(LOG_AUTHPRIV | LOG_INFO, "%s ran command %s as %s from %s",
 	    myname, cmdline, target_pw->pw_name, cwd);
```
