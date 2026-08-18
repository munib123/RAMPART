# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5054_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5054_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 27-67 of the vulnerable file.

 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/cdev.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <asm/pgtable.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/uio.h>

#include "qib.h"
#include "qib_common.h"
#include "qib_user_sdma.h"

#undef pr_fmt
#define pr_fmt(fmt) QIB_DRV_NAME ": " fmt

static int qib_open(struct inode *, struct file *);
static int qib_close(struct inode *, struct file *);
static ssize_t qib_write(struct file *, const char __user *, size_t, loff_t *);
static ssize_t qib_write_iter(struct kiocb *, struct iov_iter *);
static unsigned int qib_poll(struct file *, struct poll_table_struct *);
static int qib_mmapf(struct file *, struct vm_area_struct *);

/*
 * This is really, really weird shit - write() and writev() here
 * have completely unrelated semantics.  Sucky userland ABI,
 * film at 11.
 */
static const struct file_operations qib_file_ops = {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,6 +44,8 @@
 #include <linux/delay.h>
 #include <linux/export.h>
 #include <linux/uio.h>
+
+#include <rdma/ib.h>
 
 #include "qib.h"
 #include "qib_common.h"
@@ -2067,6 +2069,9 @@
 	ssize_t ret = 0;
 	void *dest;
 
+	if (WARN_ON_ONCE(!ib_safe_file_access(fp)))
+		return -EACCES;
+
 	if (count < sizeof(cmd.type)) {
 		ret = -EINVAL;
 		goto bail;
```
