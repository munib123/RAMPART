# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 880_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `880_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 40-86 of the vulnerable file.

#define RUN_NETWORK_LOCK_FILE	"/run/firejail/firejail-network.lock"
#define RUN_DIRECTORY_LOCK_FILE	"/run/firejail/firejail-run.lock"
#define RUN_RO_DIR	"/run/firejail/firejail.ro.dir"
#define RUN_RO_FILE	"/run/firejail/firejail.ro.file"
#define RUN_MNT_DIR	"/run/firejail/mnt"	// a tmpfs is mounted on this directory before any of the files below are created
#define RUN_CGROUP_CFG	"/run/firejail/mnt/cgroup"
#define RUN_CPU_CFG	"/run/firejail/mnt/cpu"
#define RUN_GROUPS_CFG	"/run/firejail/mnt/groups"
#define RUN_PROTOCOL_CFG	"/run/firejail/mnt/protocol"
#define RUN_NONEWPRIVS_CFG	"/run/firejail/mnt/nonewprivs"
#define RUN_HOME_DIR	"/run/firejail/mnt/home"
#define RUN_ETC_DIR	"/run/firejail/mnt/etc"
#define RUN_OPT_DIR	"/run/firejail/mnt/opt"
#define RUN_SRV_DIR	"/run/firejail/mnt/srv"
#define RUN_BIN_DIR	"/run/firejail/mnt/bin"
#define RUN_PULSE_DIR	"/run/firejail/mnt/pulse"
#define RUN_LIB_DIR	"/run/firejail/mnt/lib"
#define RUN_LIB_FILE	"/run/firejail/mnt/libfiles"
#define RUN_DNS_ETC	"/run/firejail/mnt/dns-etc"

#define RUN_SECCOMP_LIST	"/run/firejail/mnt/seccomp.list"	// list of seccomp files installed
#define RUN_SECCOMP_PROTOCOL	"/run/firejail/mnt/seccomp.protocol"	// protocol filter
#define RUN_SECCOMP_CFG	"/run/firejail/mnt/seccomp"			// configured filter
#define RUN_SECCOMP_32	"/run/firejail/mnt/seccomp.32"		// 32bit arch filter installed on 64bit architectures
#define RUN_SECCOMP_MDWX	"/run/firejail/mnt/seccomp.mdwx"		// filter for memory-deny-write-execute
#define RUN_SECCOMP_BLOCK_SECONDARY	"/run/firejail/mnt/seccomp.block_secondary"	// secondary arch blocking filter
#define RUN_SECCOMP_POSTEXEC	"/run/firejail/mnt/seccomp.postexec"		// filter for post-exec library
#define PATH_SECCOMP_DEFAULT (LIBDIR "/firejail/seccomp")			// default filter built during make
#define PATH_SECCOMP_DEFAULT_DEBUG (LIBDIR "/firejail/seccomp.debug")	// default filter built during make
#define PATH_SECCOMP_32 (LIBDIR "/firejail/seccomp.32")			// 32bit arch filter built during make
#define PATH_SECCOMP_MDWX (LIBDIR "/firejail/seccomp.mdwx")		// filter for memory-deny-write-execute built during make
#define PATH_SECCOMP_BLOCK_SECONDARY (LIBDIR "/firejail/seccomp.block_secondary")	// secondary arch blocking filter built during make


#define RUN_DEV_DIR		"/run/firejail/mnt/dev"
#define RUN_DEVLOG_FILE	"/run/firejail/mnt/devlog"

#define RUN_WHITELIST_X11_DIR	"/run/firejail/mnt/orig-x11"
#define RUN_WHITELIST_HOME_DIR	"/run/firejail/mnt/orig-home"	// default home directory masking
#define RUN_WHITELIST_RUN_DIR	"/run/firejail/mnt/orig-run"	// default run directory masking
#define RUN_WHITELIST_HOME_USER_DIR	"/run/firejail/mnt/orig-home-user"	// home directory whitelisting
#define RUN_WHITELIST_RUN_USER_DIR	"/run/firejail/mnt/orig-run-user"	// run directory whitelisting
#define RUN_WHITELIST_TMP_DIR	"/run/firejail/mnt/orig-tmp"
#define RUN_WHITELIST_MEDIA_DIR	"/run/firejail/mnt/orig-media"
#define RUN_WHITELIST_MNT_DIR	"/run/firejail/mnt/orig-mnt"
#define RUN_WHITELIST_VAR_DIR	"/run/firejail/mnt/orig-var"
#define RUN_WHITELIST_DEV_DIR	"/run/firejail/mnt/orig-dev"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,13 +57,14 @@
 #define RUN_LIB_FILE	"/run/firejail/mnt/libfiles"
 #define RUN_DNS_ETC	"/run/firejail/mnt/dns-etc"
 
-#define RUN_SECCOMP_LIST	"/run/firejail/mnt/seccomp.list"	// list of seccomp files installed
-#define RUN_SECCOMP_PROTOCOL	"/run/firejail/mnt/seccomp.protocol"	// protocol filter
-#define RUN_SECCOMP_CFG	"/run/firejail/mnt/seccomp"			// configured filter
-#define RUN_SECCOMP_32	"/run/firejail/mnt/seccomp.32"		// 32bit arch filter installed on 64bit architectures
-#define RUN_SECCOMP_MDWX	"/run/firejail/mnt/seccomp.mdwx"		// filter for memory-deny-write-execute
-#define RUN_SECCOMP_BLOCK_SECONDARY	"/run/firejail/mnt/seccomp.block_secondary"	// secondary arch blocking filter
-#define RUN_SECCOMP_POSTEXEC	"/run/firejail/mnt/seccomp.postexec"		// filter for post-exec library
+#define RUN_SECCOMP_DIR	"/run/firejail/mnt/seccomp"
+#define RUN_SECCOMP_LIST	"/run/firejail/mnt/seccomp/seccomp.list"	// list of seccomp files installed
+#define RUN_SECCOMP_PROTOCOL	"/run/firejail/mnt/seccomp/seccomp.protocol"	// protocol filter
+#define RUN_SECCOMP_CFG	"/run/firejail/mnt/seccomp/seccomp"			// configured filter
+#define RUN_SECCOMP_32		"/run/firejail/mnt/seccomp/seccomp.32"		// 32bit arch filter installed on 64bit architectures
+#define RUN_SECCOMP_MDWX	"/run/firejail/mnt/seccomp/seccomp.mdwx"		// filter for memory-deny-write-execute
+#define RUN_SECCOMP_BLOCK_SECONDARY	"/run/firejail/mnt/seccomp/seccomp.block_secondary"	// secondary arch blocking filter
+#define RUN_SECCOMP_POSTEXEC	"/run/firejail/mnt/seccomp/seccomp.postexec"		// filter for post-exec library
 #define PATH_SECCOMP_DEFAULT (LIBDIR "/firejail/seccomp")			// default filter built during make
 #define PATH_SECCOMP_DEFAULT_DEBUG (LIBDIR "/firejail/seccomp.debug")	// default filter built during make
 #define PATH_SECCOMP_32 (LIBDIR "/firejail/seccomp.32")			// 32bit arch filter built during make
@@ -95,7 +96,6 @@
 #define RUN_ASOUNDRC_FILE	"/run/firejail/mnt/.asoundrc"
 #define RUN_HOSTNAME_FILE	"/run/firejail/mnt/hostname"
 #define RUN_HOSTS_FILE	"/run/firejail/mnt/hosts"
-#define RUN_RESOLVCONF_FILE	"/run/firejail/mnt/resolv.conf"
 #define RUN_MACHINEID	"/run/firejail/mnt/machine-id"
 #define RUN_LDPRELOAD_FILE	"/run/firejail/mnt/ld.so.preload"
 #define RUN_UTMP_FILE		"/run/firejail/mnt/utmp"
```
