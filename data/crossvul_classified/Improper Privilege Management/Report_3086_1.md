# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 3086_1
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3086_1`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 418-455 of the vulnerable file.

		}
	}
	else {
		if (asprintf(&cmd, "%s/firejail/fshaper.sh --%s", LIBDIR, command) == -1)
			errExit("asprintf");
	}
	assert(cmd);

	// wipe out environment variables
	environ = NULL;

	//************************
	// build command
	//************************
	// elevate privileges
	if (setreuid(0, 0))
		errExit("setreuid");
	if (setregid(0, 0))
		errExit("setregid");

	if (!cfg.shell)
		cfg.shell = guess_shell();
	if (!cfg.shell) {
		fprintf(stderr, "Error: no POSIX shell found, please use --shell command line option\n");
		exit(1);
	}

	char *arg[4];
	arg[0] = cfg.shell;
	arg[1] = "-c";
	arg[2] = cmd;
	arg[3] = NULL;
	clearenv();
	execvp(arg[0], arg);
	
	// it will never get here
	errExit("execvp");
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -435,15 +435,8 @@
 	if (setregid(0, 0))
 		errExit("setregid");
 
-	if (!cfg.shell)
-		cfg.shell = guess_shell();
-	if (!cfg.shell) {
-		fprintf(stderr, "Error: no POSIX shell found, please use --shell command line option\n");
-		exit(1);
-	}
-
 	char *arg[4];
-	arg[0] = cfg.shell;
+	arg[0] = "/bin/sh";
 	arg[1] = "-c";
 	arg[2] = cmd;
 	arg[3] = NULL;
```
