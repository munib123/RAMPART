# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4905_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4905_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 8-48 of the vulnerable file.

 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/mount.h>
#include "ecryptfs_kernel.h"

struct ecryptfs_open_req {
	struct file **lower_file;
	struct path path;
	struct completion done;
	struct list_head kthread_ctl_list;
};

static struct ecryptfs_kthread_ctl {
#define ECRYPTFS_KTHREAD_ZOMBIE 0x00000001
	u32 flags;
	struct mutex mux;
	struct list_head req_list;
	wait_queue_head_t wait;
} ecryptfs_kthread_ctl;

static struct task_struct *ecryptfs_kthread;

/**
 * ecryptfs_threadfn
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,6 +25,7 @@
 #include <linux/slab.h>
 #include <linux/wait.h>
 #include <linux/mount.h>
+#include <linux/file.h>
 #include "ecryptfs_kernel.h"
 
 struct ecryptfs_open_req {
@@ -147,7 +148,7 @@
 	flags |= IS_RDONLY(d_inode(lower_dentry)) ? O_RDONLY : O_RDWR;
 	(*lower_file) = dentry_open(&req.path, flags, cred);
 	if (!IS_ERR(*lower_file))
-		goto out;
+		goto have_file;
 	if ((flags & O_ACCMODE) == O_RDONLY) {
 		rc = PTR_ERR((*lower_file));
 		goto out;
@@ -165,8 +166,16 @@
 	mutex_unlock(&ecryptfs_kthread_ctl.mux);
 	wake_up(&ecryptfs_kthread_ctl.wait);
 	wait_for_completion(&req.done);
-	if (IS_ERR(*lower_file))
+	if (IS_ERR(*lower_file)) {
 		rc = PTR_ERR(*lower_file);
+		goto out;
+	}
+have_file:
+	if ((*lower_file)->f_op->mmap == NULL) {
+		fput(*lower_file);
+		*lower_file = NULL;
+		rc = -EMEDIUMTYPE;
+	}
 out:
 	return rc;
 }
```
