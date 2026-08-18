# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1565_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1565_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 17-57 of the vulnerable file.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#ifndef LIBREPORT_DUMP_DIR_H_
#define LIBREPORT_DUMP_DIR_H_

/* For DIR */
#include <sys/types.h>
#include <dirent.h>

/* Fore GList */
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Utility function */
int create_symlink_lockfile(const char *filename, const char *pid_str);

enum {
    DD_FAIL_QUIETLY_ENOENT = (1 << 0),
    DD_FAIL_QUIETLY_EACCES = (1 << 1),
    /* Open symlinks. dd_* funcs don't open symlinks by default */
    DD_OPEN_FOLLOW = (1 << 2),
    DD_OPEN_READONLY = (1 << 3),
    DD_LOAD_TEXT_RETURN_NULL_ON_FAILURE = (1 << 4),
    DD_DONT_WAIT_FOR_LOCK = (1 << 5),
    /* Create the new dump directory with parent directories (mkdir -p)*/
    DD_CREATE_PARENTS = (1 << 6),
};

struct dump_dir {
    char *dd_dirname;
    DIR *next_dir;
    int locked;
    uid_t dd_uid;
    gid_t dd_gid;
    /* mode of saved files */
    mode_t mode;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,6 +34,12 @@
 
 /* Utility function */
 int create_symlink_lockfile(const char *filename, const char *pid_str);
+int create_symlink_lockfile_at(int dir_fd, const char *filename, const char *pid_str);
+
+/* Opens filename for reading relatively to a directory represented by dir_fd.
+ * The function fails if the file is symbolic link, directory or hard link.
+ */
+int secure_openat_read(int dir_fd, const char *filename);
 
 enum {
     DD_FAIL_QUIETLY_ENOENT = (1 << 0),
@@ -57,6 +63,7 @@
     mode_t mode;
     time_t dd_time;
     char *dd_type;
+    int dd_fd;
 };
 
 void dd_close(struct dump_dir *dd);
```
