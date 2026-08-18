# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in go
**Pair ID:** 1473_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1473_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```go
Lines 1-40 of the vulnerable file.

// +build linux
// +build cgo

package shared

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/chai2010/gettext-go/gettext"
)

// #cgo LDFLAGS: -lutil -lpthread
/*
#define _GNU_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <grp.h>
#include <pty.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdio.h>

// This is an adaption from https://codereview.appspot.com/4589049, to be
// included in the stdlib with the stdlib's license.

static int mygetgrgid_r(int gid, struct group *grp,
	char *buf, size_t buflen, struct group **result) {
	return getgrgid_r(gid, grp, buf, buflen, result);
}

void configure_pty(int fd) {
	struct termios term_settings;
	struct winsize win;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,15 +17,24 @@
 /*
 #define _GNU_SOURCE
 #include <sys/types.h>
+#include <sys/stat.h>
 #include <unistd.h>
 #include <stdlib.h>
 #include <grp.h>
 #include <pty.h>
 #include <errno.h>
 #include <fcntl.h>
+#include <limits.h>
 #include <string.h>
 #include <stdio.h>
-#include <stdio.h>
+
+#ifndef AT_SYMLINK_FOLLOW
+#define AT_SYMLINK_FOLLOW    0x400
+#endif
+
+#ifndef AT_EMPTY_PATH
+#define AT_EMPTY_PATH       0x1000
+#endif
 
 // This is an adaption from https://codereview.appspot.com/4589049, to be
 // included in the stdlib with the stdlib's license.
@@ -107,8 +116,81 @@
 	*master = pipefd[0];
 	*slave = pipefd[1];
 }
+
+int shiftowner(char *basepath, char *path, int uid, int gid) {
+	struct stat sb;
+	int fd, r;
+	char fdpath[PATH_MAX];
+	char realpath[PATH_MAX];
+
+	fd = open(path, O_PATH|O_NOFOLLOW);
+	if (fd < 0 ) {
+		perror("Failed open");
+		return 1;
+	}
+
+	r = sprintf(fdpath, "/proc/self/fd/%d", fd);
+	if (r < 0) {
+		perror("Failed sprintf");
+		close(fd);
+		return 1;
+	}
+
+	r = readlink(fdpath, realpath, PATH_MAX);
+	if (r < 0) {
+		perror("Failed readlink");
+		close(fd);
+		return 1;
+	}
+
+	if (strlen(realpath) < strlen(basepath)) {
+		printf("Invalid path, source is outside of basepath.\n");
+		close(fd);
+		return 1;
+	}
+
+	if (strncmp(realpath, basepath, strlen(basepath))) {
+		printf("Invalid path, source is outside of basepath.\n");
+		close(fd);
+		return 1;
+	}
+
+	r = fstat(fd, &sb);
+	if (r < 0) {
+		perror("Failed fstat");
+		close(fd);
+		return 1;
+	}
+
+	r = fchownat(fd, "", uid, gid, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW);
+	if (r < 0) {
+		perror("Failed chown");
+		close(fd);
+		return 1;
+	}
+
+	if (!S_ISLNK(sb.st_mode)) {
+		r = chmod(fdpath, sb.st_mode);
+		if (r < 0) {
+			perror("Failed chmod");
+			close(fd);
+			return 1;
+		}
+	}
+
+	close(fd);
+	return 0;
+}
 */
 import "C"
+
+func ShiftOwner(basepath string, path string, uid int, gid int) error {
+	r := C.shiftowner(C.CString(basepath), C.CString(path), C.int(uid), C.int(gid))
+	if r != 0 {
+		return fmt.Errorf("Failed to change ownership of: %s", path)
+	}
+	return nil
+}
 
 func OpenPty(uid, gid int) (master *os.File, slave *os.File, err error) {
 	fd_master := C.int(-1)
```
