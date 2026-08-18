# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 880_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `880_3`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 1036-1078 of the vulnerable file.

			printf("Current directory: %s\n", cpath);
			free(cpath);
		}
	}

	EUID_ROOT();
	// clean /tmp/.X11-unix sockets
	fs_x11();
	if (arg_x11_xorg)
		x11_xorg();

	// save original umask
	save_umask();

	//****************************
	// set security filters
	//****************************
	// save state of nonewprivs
	save_nonewprivs();

	// set capabilities
	set_caps();

	// save cpu affinity mask to CPU_CFG file
	save_cpu();

	// save cgroup in CGROUP_CFG file
	save_cgroup();

	// set seccomp
#ifdef HAVE_SECCOMP
	// install protocol filter
#ifdef SYS_socket
	if (cfg.protocol) {
		if (arg_debug)
			printf("Install protocol filter: %s\n", cfg.protocol);
		seccomp_load(RUN_SECCOMP_PROTOCOL);	// install filter
		protocol_filter_save();	// save filter in RUN_PROTOCOL_CFG
	}
	else {
		int rv = unlink(RUN_SECCOMP_PROTOCOL);
		(void) rv;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1053,9 +1053,6 @@
 	// save state of nonewprivs
 	save_nonewprivs();
 
-	// set capabilities
-	set_caps();
-
 	// save cpu affinity mask to CPU_CFG file
 	save_cpu();
 
@@ -1101,7 +1098,12 @@
 		int rv = unlink(RUN_SECCOMP_MDWX);
 		(void) rv;
 	}
-#endif
+	// make seccomp filters read-only
+	fs_rdonly(RUN_SECCOMP_DIR);
+#endif
+
+	// set capabilities
+	set_caps();
 
 	//****************************************
 	// communicate progress of sandbox set up
```
