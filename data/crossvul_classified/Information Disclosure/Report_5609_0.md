# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5609_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5609_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 193-233 of the vulnerable file.


	err = sys_ioctl(fd, cmd, (unsigned long) up_native);

	return err;
}

struct compat_video_spu_palette {
	int length;
	compat_uptr_t palette;
};

static int do_video_set_spu_palette(unsigned int fd, unsigned int cmd,
		struct compat_video_spu_palette __user *up)
{
	struct video_spu_palette __user *up_native;
	compat_uptr_t palp;
	int length, err;

	err  = get_user(palp, &up->palette);
	err |= get_user(length, &up->length);

	up_native = compat_alloc_user_space(sizeof(struct video_spu_palette));
	err  = put_user(compat_ptr(palp), &up_native->palette);
	err |= put_user(length, &up_native->length);
	if (err)
		return -EFAULT;

	err = sys_ioctl(fd, cmd, (unsigned long) up_native);

	return err;
}

#ifdef CONFIG_BLOCK
typedef struct sg_io_hdr32 {
	compat_int_t interface_id;	/* [i] 'S' for SCSI generic (required) */
	compat_int_t dxfer_direction;	/* [i] data transfer direction  */
	unsigned char cmd_len;		/* [i] SCSI command length ( <= 16 bytes) */
	unsigned char mx_sb_len;		/* [i] max length to write to sbp */
	unsigned short iovec_count;	/* [i] 0 implies no scatter gather */
	compat_uint_t dxfer_len;		/* [i] byte count of data transfer */
	compat_uint_t dxferp;		/* [i], [*io] points to data transfer memory
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -210,6 +210,8 @@
 
 	err  = get_user(palp, &up->palette);
 	err |= get_user(length, &up->length);
+	if (err)
+		return -EFAULT;
 
 	up_native = compat_alloc_user_space(sizeof(struct video_spu_palette));
 	err  = put_user(compat_ptr(palp), &up_native->palette);
```
