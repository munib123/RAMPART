# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4797_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4797_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 563-603 of the vulnerable file.

		err = -EFAULT;
		goto err_out;
	}
err_out:
	err2 = sg_finish_rem_req(srp);
	return err ? : err2 ? : count;
}

static ssize_t
sg_write(struct file *filp, const char __user *buf, size_t count, loff_t * ppos)
{
	int mxsize, cmd_size, k;
	int input_size, blocking;
	unsigned char opcode;
	Sg_device *sdp;
	Sg_fd *sfp;
	Sg_request *srp;
	struct sg_header old_hdr;
	sg_io_hdr_t *hp;
	unsigned char cmnd[SG_MAX_CDB_SIZE];

	if ((!(sfp = (Sg_fd *) filp->private_data)) || (!(sdp = sfp->parentdp)))
		return -ENXIO;
	SCSI_LOG_TIMEOUT(3, sg_printk(KERN_INFO, sdp,
				      "sg_write: count=%d\n", (int) count));
	if (atomic_read(&sdp->detaching))
		return -ENODEV;
	if (!((filp->f_flags & O_NONBLOCK) ||
	      scsi_block_when_processing_errors(sdp->device)))
		return -ENXIO;

	if (!access_ok(VERIFY_READ, buf, count))
		return -EFAULT;	/* protects following copy_from_user()s + get_user()s */
	if (count < SZ_SG_HEADER)
		return -EIO;
	if (__copy_from_user(&old_hdr, buf, SZ_SG_HEADER))
		return -EFAULT;
	blocking = !(filp->f_flags & O_NONBLOCK);
	if (old_hdr.reply_len < 0)
		return sg_new_write(sfp, filp, buf, count,
				    blocking, 0, 0, NULL);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -580,6 +580,9 @@
 	struct sg_header old_hdr;
 	sg_io_hdr_t *hp;
 	unsigned char cmnd[SG_MAX_CDB_SIZE];
+
+	if (unlikely(segment_eq(get_fs(), KERNEL_DS)))
+		return -EINVAL;
 
 	if ((!(sfp = (Sg_fd *) filp->private_data)) || (!(sdp = sfp->parentdp)))
 		return -ENXIO;
```
