# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1876_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1876_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 86-131 of the vulnerable file.

/* }}} */

int fpm_stdio_init_child(struct fpm_worker_pool_s *wp) /* {{{ */
{
#ifdef HAVE_SYSLOG_H
	if (fpm_globals.error_log_fd == ZLOG_SYSLOG) {
		closelog(); /* ensure to close syslog not to interrupt with PHP syslog code */
	} else
#endif

	/* Notice: child cannot use master error_log
	 * because not aware when being reopen
	 * else, should use if (!fpm_use_error_log())
	 */
	if (fpm_globals.error_log_fd > 0) {
		close(fpm_globals.error_log_fd);
	}
	fpm_globals.error_log_fd = -1;
	zlog_set_fd(-1);

	if (wp->listening_socket != STDIN_FILENO) {
		if (0 > dup2(wp->listening_socket, STDIN_FILENO)) {
			zlog(ZLOG_SYSERROR, "failed to init child stdio: dup2()");
			return -1;
		}
	}
	return 0;
}
/* }}} */

static void fpm_stdio_child_said(struct fpm_event_s *ev, short which, void *arg) /* {{{ */
{
	static const int max_buf_size = 1024;
	int fd = ev->fd;
	char buf[max_buf_size];
	struct fpm_child_s *child;
	int is_stdout;
	struct fpm_event_s *event;
	int fifo_in = 1, fifo_out = 1;
	int is_last_message = 0;
	int in_buf = 0;
	int res;

	if (!arg) {
		return;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,12 +103,6 @@
 	fpm_globals.error_log_fd = -1;
 	zlog_set_fd(-1);
 
-	if (wp->listening_socket != STDIN_FILENO) {
-		if (0 > dup2(wp->listening_socket, STDIN_FILENO)) {
-			zlog(ZLOG_SYSERROR, "failed to init child stdio: dup2()");
-			return -1;
-		}
-	}
 	return 0;
 }
 /* }}} */
```
