# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5054_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5054_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 31-71 of the vulnerable file.

 * SOFTWARE.
 */

#include <linux/completion.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/cdev.h>
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#include <asm/uaccess.h>

#include <rdma/ib_cm.h>
#include <rdma/ib_user_cm.h>
#include <rdma/ib_marshall.h>

MODULE_AUTHOR("Libor Michalek");
MODULE_DESCRIPTION("InfiniBand userspace Connection Manager access");
MODULE_LICENSE("Dual BSD/GPL");

struct ib_ucm_device {
	int			devnum;
	struct cdev		cdev;
	struct device		dev;
	struct ib_device	*ib_dev;
};

struct ib_ucm_file {
	struct mutex file_mutex;
	struct file *filp;
	struct ib_ucm_device *device;

	struct list_head  ctxs;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,6 +48,7 @@
 
 #include <asm/uaccess.h>
 
+#include <rdma/ib.h>
 #include <rdma/ib_cm.h>
 #include <rdma/ib_user_cm.h>
 #include <rdma/ib_marshall.h>
@@ -1103,6 +1104,9 @@
 	struct ib_ucm_cmd_hdr hdr;
 	ssize_t result;
 
+	if (WARN_ON_ONCE(!ib_safe_file_access(filp)))
+		return -EACCES;
+
 	if (len < sizeof(hdr))
 		return -EINVAL;
 
```
