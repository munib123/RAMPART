# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3525_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3525_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 7-47 of the vulnerable file.

 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-
 *
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/cdrom.h>
#include <linux/slab.h>
#include <linux/times.h>
#include <asm/uaccess.h>

#include <scsi/scsi.h>
#include <scsi/scsi_ioctl.h>
#include <scsi/scsi_cmnd.h>

struct blk_cmd_filter {
	unsigned long read_ok[BLK_SCSI_CMD_PER_LONG];
	unsigned long write_ok[BLK_SCSI_CMD_PER_LONG];
};

static struct blk_cmd_filter blk_default_cmd_filter;

/* Command group 3 is reserved and should never be used.  */
const unsigned char scsi_command_size_tbl[8] =
{
	6, 10, 10, 12,
	16, 12, 10, 10
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,6 +24,7 @@
 #include <linux/capability.h>
 #include <linux/completion.h>
 #include <linux/cdrom.h>
+#include <linux/ratelimit.h>
 #include <linux/slab.h>
 #include <linux/times.h>
 #include <asm/uaccess.h>
@@ -690,9 +691,53 @@
 }
 EXPORT_SYMBOL(scsi_cmd_ioctl);
 
+int scsi_verify_blk_ioctl(struct block_device *bd, unsigned int cmd)
+{
+	if (bd && bd == bd->bd_contains)
+		return 0;
+
+	/* Actually none of these is particularly useful on a partition,
+	 * but they are safe.
+	 */
+	switch (cmd) {
+	case SCSI_IOCTL_GET_IDLUN:
+	case SCSI_IOCTL_GET_BUS_NUMBER:
+	case SCSI_IOCTL_GET_PCI:
+	case SCSI_IOCTL_PROBE_HOST:
+	case SG_GET_VERSION_NUM:
+	case SG_SET_TIMEOUT:
+	case SG_GET_TIMEOUT:
+	case SG_GET_RESERVED_SIZE:
+	case SG_SET_RESERVED_SIZE:
+	case SG_EMULATED_HOST:
+		return 0;
+	case CDROM_GET_CAPABILITY:
+		/* Keep this until we remove the printk below.  udev sends it
+		 * and we do not want to spam dmesg about it.   CD-ROMs do
+		 * not have partitions, so we get here only for disks.
+		 */
+		return -ENOIOCTLCMD;
+	default:
+		break;
+	}
+
+	/* In particular, rule out all resets and host-specific ioctls.  */
+	printk_ratelimited(KERN_WARNING
+			   "%s: sending ioctl %x to a partition!\n", current->comm, cmd);
+
+	return capable(CAP_SYS_RAWIO) ? 0 : -ENOIOCTLCMD;
+}
+EXPORT_SYMBOL(scsi_verify_blk_ioctl);
+
 int scsi_cmd_blk_ioctl(struct block_device *bd, fmode_t mode,
 		       unsigned int cmd, void __user *arg)
 {
+	int ret;
+
+	ret = scsi_verify_blk_ioctl(bd, cmd);
+	if (ret < 0)
+		return ret;
+
 	return scsi_cmd_ioctl(bd->bd_disk->queue, bd->bd_disk, mode, cmd, arg);
 }
 EXPORT_SYMBOL(scsi_cmd_blk_ioctl);
```
