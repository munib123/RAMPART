# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1661_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1661_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 306-333 of the vulnerable file.

		return EXIT_FAILURE;
	}
#endif
	if (!info.shell) {
		info.shell = ask_new_shell(_("New shell"), oldshell);
		if (!info.shell)
			return EXIT_SUCCESS;
	}

	check_shell(info.shell);

	if (!nullshell && strcmp(oldshell, info.shell) == 0)
		errx(EXIT_SUCCESS, _("Shell not changed."));

#ifdef HAVE_LIBUSER
	if (set_value_libuser("chsh", pw->pw_name, uid,
	    LU_LOGINSHELL, info.shell) < 0)
		errx(EXIT_FAILURE, _("Shell *NOT* changed.  Try again later."));
#else
	pw->pw_shell = info.shell;
	if (setpwnam(pw) < 0)
		err(EXIT_FAILURE, _("setpwnam failed\n"
			"Shell *NOT* changed.  Try again later."));
#endif

	printf(_("Shell changed.\n"));
	return EXIT_SUCCESS;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -323,7 +323,7 @@
 		errx(EXIT_FAILURE, _("Shell *NOT* changed.  Try again later."));
 #else
 	pw->pw_shell = info.shell;
-	if (setpwnam(pw) < 0)
+	if (setpwnam(pw, ".chsh") < 0)
 		err(EXIT_FAILURE, _("setpwnam failed\n"
 			"Shell *NOT* changed.  Try again later."));
 #endif
```
