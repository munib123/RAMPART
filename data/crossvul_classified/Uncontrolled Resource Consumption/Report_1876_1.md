# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1876_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1876_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 129-169 of the vulnerable file.

		for (child = wp->children; child; child = child->next) {
			if (child->pid == pid) {
				break;
			}
		}

		if (child) break;
	}

	if (!child) {
		return 0;
	}

	return child;
}
/* }}} */

static void fpm_child_init(struct fpm_worker_pool_s *wp) /* {{{ */
{
	fpm_globals.max_requests = wp->config->pm_max_requests;

	if (0 > fpm_stdio_init_child(wp)  ||
	    0 > fpm_log_init_child(wp)    ||
	    0 > fpm_status_init_child(wp) ||
	    0 > fpm_unix_init_child(wp)   ||
	    0 > fpm_signals_init_child()  ||
	    0 > fpm_env_init_child(wp)    ||
	    0 > fpm_php_init_child(wp)) {

		zlog(ZLOG_ERROR, "[pool %s] child failed to initialize", wp->config->name);
		exit(FPM_EXIT_SOFTWARE);
	}
}
/* }}} */

int fpm_children_free(struct fpm_child_s *child) /* {{{ */
{
	struct fpm_child_s *next;

	for (; child; child = next) {
		next = child->next;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -146,6 +146,7 @@
 static void fpm_child_init(struct fpm_worker_pool_s *wp) /* {{{ */
 {
 	fpm_globals.max_requests = wp->config->pm_max_requests;
+	fpm_globals.listening_socket = dup(wp->listening_socket);
 
 	if (0 > fpm_stdio_init_child(wp)  ||
 	    0 > fpm_log_init_child(wp)    ||
```
