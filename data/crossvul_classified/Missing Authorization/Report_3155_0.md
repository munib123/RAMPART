# CrossVul Fix Pair: Missing Authorization in c
**Pair ID:** 3155_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3155_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```c
Lines 32-72 of the vulnerable file.

#include <sched.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <sys/param.h>

#include "config.h"
#include "utils.h"
#include "network.h"

static void usage(char *me, bool fail)
{
	fprintf(stderr, "Usage: %s lxcpath name pid type bridge nicname\n", me);
	fprintf(stderr, " nicname is the name to use inside the container\n");
	exit(fail ? 1 : 0);
}

static char *lxcpath, *lxcname;

static int open_and_lock(char *path)
{
	int fd;
	struct flock lk;

	fd = open(path, O_RDWR|O_CREAT, S_IWUSR | S_IRUSR);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n",
			path, strerror(errno));
		return(fd);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,6 +50,14 @@
 #include "utils.h"
 #include "network.h"
 
+#define usernic_debug_stream(stream, format, ...)                              \
+	do {                                                                   \
+		fprintf(stream, "%s: %d: %s: " format, __FILE__, __LINE__,     \
+			__func__, __VA_ARGS__);                                \
+	} while (false)
+
+#define usernic_error(format, ...) usernic_debug_stream(stderr, format, __VA_ARGS__)
+
 static void usage(char *me, bool fail)
 {
 	fprintf(stderr, "Usage: %s lxcpath name pid type bridge nicname\n", me);
@@ -670,68 +678,115 @@
 }
 
 #define VETH_DEF_NAME "eth%d"
-
 static int rename_in_ns(int pid, char *oldname, char **newnamep)
 {
-	int fd = -1, ofd = -1, ret, ifindex = -1;
+	uid_t ruid, suid, euid;
+	int fret = -1;
+	int fd = -1, ifindex = -1, ofd = -1, ret;
 	bool grab_newname = false;
 
 	ofd = lxc_preserve_ns(getpid(), "net");
 	if (ofd < 0) {
-		fprintf(stderr, "Failed opening network namespace path for '%d'.", getpid());
-		return -1;
+		usernic_error("Failed opening network namespace path for '%d'.", getpid());
+		return fret;
 	}
 
 	fd = lxc_preserve_ns(pid, "net");
 	if (fd < 0) {
-		fprintf(stderr, "Failed opening network namespace path for '%d'.", pid);
-		return -1;
-	}
-
-	if (setns(fd, 0) < 0) {
-		fprintf(stderr, "setns to container network namespace\n");
-		goto out_err;
-	}
-	close(fd); fd = -1;
+		usernic_error("Failed opening network namespace path for '%d'.", pid);
+		goto do_partial_cleanup;
+	}
+
+	ret = getresuid(&ruid, &euid, &suid);
+	if (ret < 0) {
+		usernic_error("Failed to retrieve real, effective, and saved "
+			      "user IDs: %s\n",
+			      strerror(errno));
+		goto do_partial_cleanup;
+	}
+
+	ret = setns(fd, CLONE_NEWNET);
+	close(fd);
+	fd = -1;
+	if (ret < 0) {
+		usernic_error("Failed to setns() to the network namespace of "
+			      "the container with PID %d: %s.\n",
+			      pid, strerror(errno));
+		goto do_partial_cleanup;
+	}
+
+	ret = setresuid(ruid, ruid, 0);
+	if (ret < 0) {
+		usernic_error("Failed to drop privilege by setting effective "
+			      "user id and real user id to %d, and saved user "
+			      "ID to 0: %s.\n",
+			      ruid, strerror(errno));
+		// COMMENT(brauner): It's ok to jump to do_full_cleanup here
+		// since setresuid() will succeed when trying to set real,
+		// effective, and saved to values they currently have.
+		goto do_full_cleanup;
+	}
+
 	if (!*newnamep) {
 		grab_newname = true;
 		*newnamep = VETH_DEF_NAME;
-		if (!(ifindex = if_nametoindex(oldname))) {
-			fprintf(stderr, "failed to get netdev index\n");
-			goto out_err;
-		}
-	}
-	if ((ret = lxc_netdev_rename_by_name(oldname, *newnamep)) < 0) {
-		fprintf(stderr, "Error %d renaming netdev %s to %s in container\n", ret, oldname, *newnamep);
-		goto out_err;
-	}
+
+		ifindex = if_nametoindex(oldname);
+		if (!ifindex) {
+			usernic_error("Failed to get netdev index: %s.\n", strerror(errno));
+			goto do_full_cleanup;
+		}
+	}
+
+	ret = lxc_netdev_rename_by_name(oldname, *newnamep);
+	if (ret < 0) {
+		usernic_error("Error %d renaming netdev %s to %s in container.\n", ret, oldname, *newnamep);
+		goto do_full_cleanup;
+	}
+
 	if (grab_newname) {
-		char ifname[IFNAMSIZ], *namep = ifname;
+		char ifname[IFNAMSIZ];
+		char *namep = ifname;
+
 		if (!if_indextoname(ifindex, namep)) {
-			fprintf(stderr, "Failed to get new netdev name\n");
-			goto out_err;
-		}
+			usernic_error("Failed to get new netdev name: %s.\n", strerror(errno));
+			goto do_full_cleanup;
+		}
+
 		*newnamep = strdup(namep);
 		if (!*newnamep)
-			goto out_err;
-	}
-	if (setns(ofd, 0) < 0) {
-		fprintf(stderr, "Error returning to original netns\n");
-		close(ofd);
-		return -1;
-	}
-	close(ofd);
-
-	return 0;
-
-out_err:
-	if (ofd >= 0)
-		close(ofd);
-	if (setns(ofd, 0) < 0)
-		fprintf(stderr, "Error returning to original network namespace\n");
+			goto do_full_cleanup;
+	}
+
+	fret = 0;
+
+do_full_cleanup:
+	ret = setresuid(ruid, euid, suid);
+	if (ret < 0) {
+		usernic_error("Failed to restore privilege by setting effective "
+			      "user id to %d, real user id to %d, and saved user "
+			      "ID to %d: %s.\n",
+			      ruid, euid, suid, strerror(errno));
+		fret = -1;
+		// COMMENT(brauner): setns() should fail if setresuid() doesn't
+		// succeed but there's no harm in falling through; keeps the
+		// code cleaner.
+	}
+
+	ret = setns(ofd, CLONE_NEWNET);
+	if (ret < 0) {
+		usernic_error("Failed to setns() to original network namespace "
+			      "of PID %d: %s.\n",
+			      ofd, strerror(errno));
+		fret = -1;
+	}
+
+do_partial_cleanup:
 	if (fd >= 0)
 		close(fd);
-	return -1;
+	close(ofd);
+
+	return fret;
 }
 
 /*
```
