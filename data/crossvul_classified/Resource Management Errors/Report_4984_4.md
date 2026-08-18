# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 4984_4
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4984_4`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1740-1780 of the vulnerable file.

		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax_coredump,
		.extra1		= &zero,
		.extra2		= &two,
	},
#if defined(CONFIG_BINFMT_MISC) || defined(CONFIG_BINFMT_MISC_MODULE)
	{
		.procname	= "binfmt_misc",
		.mode		= 0555,
		.child		= sysctl_mount_point,
	},
#endif
	{
		.procname	= "pipe-max-size",
		.data		= &pipe_max_size,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &pipe_proc_fn,
		.extra1		= &pipe_min_size,
	},
	{ }
};

static struct ctl_table debug_table[] = {
#ifdef CONFIG_SYSCTL_EXCEPTION_TRACE
	{
		.procname	= "exception-trace",
		.data		= &show_unhandled_signals,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
#endif
#if defined(CONFIG_OPTPROBES)
	{
		.procname	= "kprobes-optimization",
		.data		= &sysctl_kprobes_optimization,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_kprobes_optimization_handler,
		.extra1		= &zero,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1757,6 +1757,20 @@
 		.proc_handler	= &pipe_proc_fn,
 		.extra1		= &pipe_min_size,
 	},
+	{
+		.procname	= "pipe-user-pages-hard",
+		.data		= &pipe_user_pages_hard,
+		.maxlen		= sizeof(pipe_user_pages_hard),
+		.mode		= 0644,
+		.proc_handler	= proc_doulongvec_minmax,
+	},
+	{
+		.procname	= "pipe-user-pages-soft",
+		.data		= &pipe_user_pages_soft,
+		.maxlen		= sizeof(pipe_user_pages_soft),
+		.mode		= 0644,
+		.proc_handler	= proc_doulongvec_minmax,
+	},
 	{ }
 };
 
```
