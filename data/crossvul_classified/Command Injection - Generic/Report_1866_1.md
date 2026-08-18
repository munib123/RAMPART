# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in c
**Pair ID:** 1866_1
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1866_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```c
Lines 31-71 of the vulnerable file.

#include <assert.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <limits.h>
#ifdef USE_FLOCK
#include <sys/file.h>
#endif
#ifdef LINENOISE
#include <dirent.h>
#include <libgen.h>
#endif

#define _GNU_SOURCE
#include <getopt.h>

#include "term.h"
#ifdef LINENOISE
#include "linenoise-1.0/linenoise.h"
#endif

/**********************************************************************/

/* parity modes names */
const char *parity_str[] = {
	[P_NONE] = "none",
	[P_EVEN] = "even",
	[P_ODD] = "odd",
	[P_MARK] = "mark",
	[P_SPACE] = "space",
};

/* flow control modes names */
const char *flow_str[] = {
	[FC_NONE] = "none",
	[FC_RTSCTS] = "RTS/CTS",
	[FC_XONXOFF] = "xon/xoff",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,6 +48,7 @@
 #define _GNU_SOURCE
 #include <getopt.h>
 
+#include "split.h"
 #include "term.h"
 #ifdef LINENOISE
 #include "linenoise-1.0/linenoise.h"
@@ -721,6 +722,9 @@
 
 /**********************************************************************/
 
+#define RUNCMD_ARGS_MAX 32
+#define RUNCMD_EXEC_FAIL 126
+
 void
 establish_child_signal_handlers (void)
 {
@@ -735,10 +739,8 @@
 	sigaction (SIGTERM, &dfl_action, NULL);
 }
 
-#define EXEC "exec "
-
 int
-run_cmd(int fd, ...)
+run_cmd(int fd, const char *cmd, const char *args_extra)
 {
 	pid_t pid;
 	sigset_t sigm, sigm_old;
@@ -781,8 +783,10 @@
 	} else {
 		/* child: external program */
 		long fl;
-		char cmd[512];
-
+		int argc;
+		char *argv[RUNCMD_ARGS_MAX + 1];
+		int r;
+			
 		/* unmanage terminal, and reset it to canonical mode */
 		term_remove(STI);
 		/* unmanage serial port fd, without reset */
@@ -796,36 +800,35 @@
 		close(STO);
 		dup2(fd, STI);
 		dup2(fd, STO);
-		{
-			/* build command-line */
-			char *c, *ce;
-			const char *s;
-			int n;
-			va_list vls;
+		
+		/* build command arguments vector */
+		argc = 0;
+		r = split_quoted(cmd, &argc, argv, RUNCMD_ARGS_MAX);
+		if ( r < 0 ) {
+			fd_printf(STDERR_FILENO, "Cannot parse command\n");
+			exit(RUNCMD_EXEC_FAIL);
+		}
+		r = split_quoted(args_extra, &argc, argv, RUNCMD_ARGS_MAX);
+		if ( r < 0 ) {
+			fd_printf(STDERR_FILENO, "Cannot parse extra args\n");
+			exit(RUNCMD_EXEC_FAIL);
+		}
+		if ( argc < 1 ) {
+			fd_printf(STDERR_FILENO, "No command given\n");
+			exit(RUNCMD_EXEC_FAIL);
+		}	
+		argv[argc] = NULL;
 			
-			strcpy(cmd, EXEC);
-			c = &cmd[sizeof(EXEC)- 1];
-			ce = cmd + sizeof(cmd) - 1;
-			va_start(vls, fd);
-			while ( (s = va_arg(vls, const char *)) ) {
-				n = strlen(s);
-				if ( c + n + 1 >= ce ) break;
-				memcpy(c, s, n); c += n;
-				*c++ = ' ';
-			}
-			va_end(vls);
-			*c = '\0';
-		}
 		/* run extenral command */
-		fd_printf(STDERR_FILENO, "%s\n", &cmd[sizeof(EXEC) - 1]);
+		fd_printf(STDERR_FILENO, "$ %s %s\n", cmd, args_extra);
 		establish_child_signal_handlers();
 		sigprocmask(SIG_SETMASK, &sigm_old, NULL);
-		execl("/bin/sh", "sh", "-c", cmd, NULL);
-		exit(42);
-	}
-}
-
-#undef EXEC
+		execvp(argv[0], argv);
+
+		fd_printf(STDERR_FILENO, "exec: %s\n", strerror(errno));
+		exit(RUNCMD_EXEC_FAIL);
+	}
+}
 
 /**********************************************************************/
 
@@ -944,7 +947,7 @@
 			fd_printf(STO, "*** cannot read filename ***\r\n");
 			break;
 		}
-		run_cmd(tty_fd, xfr_cmd, fname, NULL);
+		run_cmd(tty_fd, xfr_cmd, fname);
 		free(fname);
 		break;
 	case KEY_BREAK:
```
