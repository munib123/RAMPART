# CrossVul Fix Pair: DEPRECATED: Containment Errors (Container Errors) in c
**Pair ID:** 1396_1
**Vulnerability Class:** DEPRECATED- Containment Errors (Container Errors)
**CWE:** CWE-216
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1396_1`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Containment Errors (Container Errors) - This entry has been deprecated, as it was not effective as a weakness and was structured more like a category.

## Vulnerable Code
```c
Lines 517-557 of the vulnerable file.


	/*
	 * The ordering in which we join namespaces is important. We should
	 * always join the user namespace *first*. This is all guaranteed
	 * from the container_linux.go side of this, so we're just going to
	 * follow the order given to us.
	 */

	for (i = 0; i < num; i++) {
		struct namespace_t ns = namespaces[i];

		if (setns(ns.fd, ns.ns) < 0)
			bail("failed to setns to %s", ns.path);

		close(ns.fd);
	}

	free(namespaces);
}

void nsexec(void)
{
	int pipenum;
	jmp_buf env;
	int sync_child_pipe[2], sync_grandchild_pipe[2];
	struct nlconfig_t config = { 0 };

	/*
	 * If we don't have an init pipe, just return to the go routine.
	 * We'll only get an init pipe for start or exec.
	 */
	pipenum = initpipe();
	if (pipenum == -1)
		return;

	/* Parse all of the netlink configuration. */
	nl_parse(pipenum, &config);

	/* Set oom_score_adj. This has to be done before !dumpable because
	 * /proc/self/oom_score_adj is not writeable unless you're an privileged
	 * user (if !dumpable is set). All children inherit their parent's
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -534,6 +534,9 @@
 	free(namespaces);
 }
 
+/* Defined in cloned_binary.c. */
+extern int ensure_cloned_binary(void);
+
 void nsexec(void)
 {
 	int pipenum;
@@ -548,6 +551,14 @@
 	pipenum = initpipe();
 	if (pipenum == -1)
 		return;
+
+	/*
+	 * We need to re-exec if we are not in a cloned binary. This is necessary
+	 * to ensure that containers won't be able to access the host binary
+	 * through /proc/self/exe. See CVE-2019-5736.
+	 */
+	if (ensure_cloned_binary() < 0)
+		bail("could not ensure we are a cloned binary");
 
 	/* Parse all of the netlink configuration. */
 	nl_parse(pipenum, &config);
```
