# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 1470_0
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1470_0`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 58-98 of the vulnerable file.

#include "lsm/lsm.h"
#include "confile.h"

#if HAVE_SYS_PERSONALITY_H
#include <sys/personality.h>
#endif

#ifndef SOCK_CLOEXEC
#  define SOCK_CLOEXEC                02000000
#endif

#ifndef MS_REC
#define MS_REC 16384
#endif

#ifndef MS_SLAVE
#define MS_SLAVE (1<<19)
#endif

lxc_log_define(lxc_attach, lxc);

static struct lxc_proc_context_info *lxc_proc_get_context_info(pid_t pid)
{
	struct lxc_proc_context_info *info = calloc(1, sizeof(*info));
	FILE *proc_file;
	char proc_fn[MAXPATHLEN];
	char *line = NULL;
	size_t line_bufsz = 0;
	int ret, found;

	if (!info) {
		SYSERROR("Could not allocate memory.");
		return NULL;
	}

	/* read capabilities */
	snprintf(proc_fn, MAXPATHLEN, "/proc/%d/status", pid);

	proc_file = fopen(proc_fn, "r");
	if (!proc_file) {
		SYSERROR("Could not open %s", proc_fn);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,6 +75,82 @@
 #endif
 
 lxc_log_define(lxc_attach, lxc);
+
+int lsm_set_label_at(int procfd, int on_exec, char* lsm_label) {
+	int labelfd = -1;
+	int ret = 0;
+	const char* name;
+	char* command = NULL;
+
+	name = lsm_name();
+
+	if (strcmp(name, "nop") == 0)
+		goto out;
+
+	if (strcmp(name, "none") == 0)
+		goto out;
+
+	/* We don't support on-exec with AppArmor */
+	if (strcmp(name, "AppArmor") == 0)
+		on_exec = 0;
+
+	if (on_exec) {
+		labelfd = openat(procfd, "self/attr/exec", O_RDWR);
+	}
+	else {
+		labelfd = openat(procfd, "self/attr/current", O_RDWR);
+	}
+
+	if (labelfd < 0) {
+		SYSERROR("Unable to open LSM label");
+		ret = -1;
+		goto out;
+	}
+
+	if (strcmp(name, "AppArmor") == 0) {
+		int size;
+
+		command = malloc(strlen(lsm_label) + strlen("changeprofile ") + 1);
+		if (!command) {
+			SYSERROR("Failed to write apparmor profile");
+			ret = -1;
+			goto out;
+		}
+
+		size = sprintf(command, "changeprofile %s", lsm_label);
+		if (size < 0) {
+			SYSERROR("Failed to write apparmor profile");
+			ret = -1;
+			goto out;
+		}
+
+		if (write(labelfd, command, size + 1) < 0) {
+			SYSERROR("Unable to set LSM label");
+			ret = -1;
+			goto out;
+		}
+	}
+	else if (strcmp(name, "SELinux") == 0) {
+		if (write(labelfd, lsm_label, strlen(lsm_label) + 1) < 0) {
+			SYSERROR("Unable to set LSM label");
+			ret = -1;
+			goto out;
+		}
+	}
+	else {
+		ERROR("Unable to restore label for unknown LSM: %s", name);
+		ret = -1;
+		goto out;
+	}
+
+out:
+	free(command);
+
+	if (labelfd != -1)
+		close(labelfd);
+
+	return ret;
+}
 
 static struct lxc_proc_context_info *lxc_proc_get_context_info(pid_t pid)
 {
@@ -570,6 +646,7 @@
 	struct lxc_proc_context_info* init_ctx;
 	lxc_attach_exec_t exec_function;
 	void* exec_payload;
+	int procfd;
 };
 
 static int attach_child_main(void* data);
@@ -622,6 +699,7 @@
 	char* cwd;
 	char* new_cwd;
 	int ipc_sockets[2];
+	int procfd;
 	signed long personality;
 
 	if (!options)
@@ -833,6 +911,13 @@
 		rexit(-1);
 	}
 
+	procfd = open("/proc", O_DIRECTORY | O_RDONLY);
+	if (procfd < 0) {
+		SYSERROR("Unable to open /proc");
+		shutdown(ipc_sockets[1], SHUT_RDWR);
+		rexit(-1);
+	}
+
 	/* attach now, create another subprocess later, since pid namespaces
 	 * only really affect the children of the current process
 	 */
@@ -860,7 +945,8 @@
 			.options = options,
 			.init_ctx = init_ctx,
 			.exec_function = exec_function,
-			.exec_payload = exec_payload
+			.exec_payload = exec_payload,
+			.procfd = procfd
 		};
 		/* We use clone_parent here to make this subprocess a direct child of
 		 * the initial process. Then this intermediate process can exit and
@@ -898,6 +984,7 @@
 {
 	struct attach_clone_payload* payload = (struct attach_clone_payload*)data;
 	int ipc_socket = payload->ipc_socket;
+	int procfd = payload->procfd;
 	lxc_attach_options_t* options = payload->options;
 	struct lxc_proc_context_info* init_ctx = payload->init_ctx;
 #if HAVE_SYS_PERSONALITY_H
@@ -1038,21 +1125,11 @@
 	close(ipc_socket);
 
 	/* set new apparmor profile/selinux context */
-	if ((options->namespaces & CLONE_NEWNS) && (options->attach_flags & LXC_ATTACH_LSM)) {
+	if ((options->namespaces & CLONE_NEWNS) && (options->attach_flags & LXC_ATTACH_LSM) && init_ctx->lsm_label) {
 		int on_exec;
-		int proc_mounted;
 
 		on_exec = options->attach_flags & LXC_ATTACH_LSM_EXEC ? 1 : 0;
-		proc_mounted = mount_proc_if_needed("/");
-		if (proc_mounted == -1) {
-			ERROR("Error mounting a sane /proc");
-			rexit(-1);
-		}
-		ret = lsm_process_label_set(init_ctx->lsm_label,
-				init_ctx->container->lxc_conf, 0, on_exec);
-		if (proc_mounted)
-			umount("/proc");
-		if (ret < 0) {
+		if (lsm_set_label_at(procfd, on_exec, init_ctx->lsm_label) < 0) {
 			rexit(-1);
 		}
 	}
@@ -1103,6 +1180,9 @@
 		}
 	}
 
+	/* we don't need proc anymore */
+	close(procfd);
+
 	/* we're done, so we can now do whatever the user intended us to do */
 	rexit(payload->exec_function(payload->exec_payload));
 }
```
