# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 3152_2
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3152_2`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 11-51 of the vulnerable file.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#define _XOPEN_SOURCE 500
#include "firejail.h"
#include <ftw.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <dirent.h>
#include <grp.h>
#include <sys/ioctl.h>
#include <termios.h>

#define MAX_GROUPS 1024
// drop privileges
// - for root group or if nogroups is set, supplementary groups are not configured
void drop_privs(int nogroups) {
	EUID_ROOT();
	gid_t gid = getgid();

	// configure supplementary groups
	if (gid == 0 || nogroups) {
		if (setgroups(0, NULL) < 0)
			errExit("setgroups");
		if (arg_debug)
			printf("Username %s, no supplementary groups\n", cfg.username);
	}
	else {
		assert(cfg.username);
		gid_t groups[MAX_GROUPS];
		int ngroups = MAX_GROUPS;
		int rv = getgrouplist(cfg.username, gid, groups, &ngroups);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,7 @@
 #include <grp.h>
 #include <sys/ioctl.h>
 #include <termios.h>
+#include <sys/wait.h>
 
 #define MAX_GROUPS 1024
 // drop privileges
@@ -219,6 +220,45 @@
 	return 0;
 }
 
+// return -1 if error, 0 if no error
+void copy_file_as_user(const char *srcname, const char *destname, uid_t uid, gid_t gid, mode_t mode) {
+	pid_t child = fork();
+	if (child < 0)
+		errExit("fork");
+	if (child == 0) {
+		// drop privileges
+		drop_privs(0);
+
+		// copy, set permissions and ownership
+		int rv = copy_file(srcname, destname, uid, gid, mode);
+		if (rv)
+			fprintf(stderr, "Warning: cannot transfer .Xauthority in private home directory\n");
+		_exit(0);
+	}
+	// wait for the child to finish
+	waitpid(child, NULL, 0);
+}
+
+// return -1 if error, 0 if no error
+void touch_file_as_user(const char *fname, uid_t uid, gid_t gid, mode_t mode) {
+	pid_t child = fork();
+	if (child < 0)
+		errExit("fork");
+	if (child == 0) {
+		// drop privileges
+		drop_privs(0);
+
+		FILE *fp = fopen(fname, "w");
+		if (fp) {
+			fprintf(fp, "\n");
+			SET_PERMS_STREAM(fp, uid, gid, mode);
+			fclose(fp);
+		}
+		_exit(0);
+	}
+	// wait for the child to finish
+	waitpid(child, NULL, 0);
+}
 
 // return 1 if the file is a directory
 int is_dir(const char *fname) {
```
