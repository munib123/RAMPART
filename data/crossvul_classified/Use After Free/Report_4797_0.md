# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4797_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4797_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 638-678 of the vulnerable file.

		nr_commands--;
		buf += sizeof(struct sg_io_v4);
		*bytes_written += sizeof(struct sg_io_v4);
	}

	if (bc)
		bsg_free_command(bc);

	return ret;
}

static ssize_t
bsg_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct bsg_device *bd = file->private_data;
	ssize_t bytes_written;
	int ret;

	dprintk("%s: write %Zd bytes\n", bd->name, count);

	bsg_set_block(bd, file);

	bytes_written = 0;
	ret = __bsg_write(bd, buf, count, &bytes_written,
			  file->f_mode & FMODE_WRITE);

	*ppos = bytes_written;

	/*
	 * return bytes written on non-fatal errors
	 */
	if (!bytes_written || err_block_err(ret))
		bytes_written = ret;

	dprintk("%s: returning %Zd\n", bd->name, bytes_written);
	return bytes_written;
}

static struct bsg_device *bsg_alloc_device(void)
{
	struct bsg_device *bd;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -655,6 +655,9 @@
 
 	dprintk("%s: write %Zd bytes\n", bd->name, count);
 
+	if (unlikely(segment_eq(get_fs(), KERNEL_DS)))
+		return -EINVAL;
+
 	bsg_set_block(bd, file);
 
 	bytes_written = 0;
```
