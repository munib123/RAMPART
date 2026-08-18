# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 1510_0
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1510_0`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 1-41 of the vulnerable file.

/*
 * sysctl_net_llc.c: sysctl interface to LLC net subsystem.
 *
 * Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 */

#include <linux/mm.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <net/net_namespace.h>
#include <net/llc.h>

#ifndef CONFIG_SYSCTL
#error This file should not be compiled without CONFIG_SYSCTL defined
#endif

static struct ctl_table llc2_timeout_table[] = {
	{
		.procname	= "ack",
		.data		= &sysctl_llc2_ack_timeout,
		.maxlen		= sizeof(long),
		.mode		= 0644,
		.proc_handler   = proc_dointvec_jiffies,
	},
	{
		.procname	= "busy",
		.data		= &sysctl_llc2_busy_timeout,
		.maxlen		= sizeof(long),
		.mode		= 0644,
		.proc_handler   = proc_dointvec_jiffies,
	},
	{
		.procname	= "p",
		.data		= &sysctl_llc2_p_timeout,
		.maxlen		= sizeof(long),
		.mode		= 0644,
		.proc_handler   = proc_dointvec_jiffies,
	},
	{
		.procname	= "rej",
		.data		= &sysctl_llc2_rej_timeout,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,28 +18,28 @@
 	{
 		.procname	= "ack",
 		.data		= &sysctl_llc2_ack_timeout,
-		.maxlen		= sizeof(long),
+		.maxlen		= sizeof(sysctl_llc2_ack_timeout),
 		.mode		= 0644,
 		.proc_handler   = proc_dointvec_jiffies,
 	},
 	{
 		.procname	= "busy",
 		.data		= &sysctl_llc2_busy_timeout,
-		.maxlen		= sizeof(long),
+		.maxlen		= sizeof(sysctl_llc2_busy_timeout),
 		.mode		= 0644,
 		.proc_handler   = proc_dointvec_jiffies,
 	},
 	{
 		.procname	= "p",
 		.data		= &sysctl_llc2_p_timeout,
-		.maxlen		= sizeof(long),
+		.maxlen		= sizeof(sysctl_llc2_p_timeout),
 		.mode		= 0644,
 		.proc_handler   = proc_dointvec_jiffies,
 	},
 	{
 		.procname	= "rej",
 		.data		= &sysctl_llc2_rej_timeout,
-		.maxlen		= sizeof(long),
+		.maxlen		= sizeof(sysctl_llc2_rej_timeout),
 		.mode		= 0644,
 		.proc_handler   = proc_dointvec_jiffies,
 	},
```
