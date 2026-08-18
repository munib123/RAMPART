# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5054_6
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5054_6`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 17-57 of the vulnerable file.

 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(_RDMA_IB_H)
#define _RDMA_IB_H

#include <linux/types.h>

struct ib_addr {
	union {
		__u8		uib_addr8[16];
		__be16		uib_addr16[8];
		__be32		uib_addr32[4];
		__be64		uib_addr64[2];
	} ib_u;
#define sib_addr8		ib_u.uib_addr8
#define sib_addr16		ib_u.uib_addr16
#define sib_addr32		ib_u.uib_addr32
#define sib_addr64		ib_u.uib_addr64
#define sib_raw			ib_u.uib_addr8
#define sib_subnet_prefix	ib_u.uib_addr64[0]
#define sib_interface_id	ib_u.uib_addr64[1]
};

static inline int ib_addr_any(const struct ib_addr *a)
{
	return ((a->sib_addr64[0] | a->sib_addr64[1]) == 0);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,6 +34,7 @@
 #define _RDMA_IB_H
 
 #include <linux/types.h>
+#include <linux/sched.h>
 
 struct ib_addr {
 	union {
@@ -86,4 +87,19 @@
 	__u64			sib_scope_id;
 };
 
+/*
+ * The IB interfaces that use write() as bi-directional ioctl() are
+ * fundamentally unsafe, since there are lots of ways to trigger "write()"
+ * calls from various contexts with elevated privileges. That includes the
+ * traditional suid executable error message writes, but also various kernel
+ * interfaces that can write to file descriptors.
+ *
+ * This function provides protection for the legacy API by restricting the
+ * calling context.
+ */
+static inline bool ib_safe_file_access(struct file *filp)
+{
+	return filp->f_cred == current_cred() && segment_eq(get_fs(), USER_DS);
+}
+
 #endif /* _RDMA_IB_H */
```
