# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 4731_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4731_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 276-335 of the vulnerable file.

			type = "v4l2";
			break;
		}
		printk("%s", v4l2_ioctls[_IOC_NR(cmd)]);
		return;
	default:
		type = "unknown";
	}

	switch (_IOC_DIR(cmd)) {
	case _IOC_NONE:              dir = "--"; break;
	case _IOC_READ:              dir = "r-"; break;
	case _IOC_WRITE:             dir = "-w"; break;
	case _IOC_READ | _IOC_WRITE: dir = "rw"; break;
	default:                     dir = "*ERR*"; break;
	}
	printk("%s ioctl '%c', dir=%s, #%d (0x%08x)",
		type, _IOC_TYPE(cmd), dir, _IOC_NR(cmd), cmd);
}
EXPORT_SYMBOL(v4l_printk_ioctl);

/*
 * helper function -- handles userspace copying for ioctl arguments
 * Obsolete usercopy function - Should be removed soon
 */
long
video_usercopy(struct file *file, unsigned int cmd, unsigned long arg,
		v4l2_kioctl func)
{
	char	sbuf[128];
	void    *mbuf = NULL;
	void	*parg = NULL;
	long	err  = -EINVAL;
	int     is_ext_ctrl;
	size_t  ctrls_size = 0;
	void __user *user_ptr = NULL;

	is_ext_ctrl = (cmd == VIDIOC_S_EXT_CTRLS || cmd == VIDIOC_G_EXT_CTRLS ||
		       cmd == VIDIOC_TRY_EXT_CTRLS);

	/*  Copy arguments into temp kernel buffer  */
	switch (_IOC_DIR(cmd)) {
	case _IOC_NONE:
		parg = NULL;
		break;
	case _IOC_READ:
	case _IOC_WRITE:
	case (_IOC_WRITE | _IOC_READ):
		if (_IOC_SIZE(cmd) <= sizeof(sbuf)) {
			parg = sbuf;
		} else {
			/* too big to allocate from stack */
			mbuf = kmalloc(_IOC_SIZE(cmd), GFP_KERNEL);
			if (NULL == mbuf)
				return -ENOMEM;
			parg = mbuf;
		}

		err = -EFAULT;
		if (_IOC_DIR(cmd) & _IOC_WRITE)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -294,101 +294,6 @@
 }
 EXPORT_SYMBOL(v4l_printk_ioctl);
 
-/*
- * helper function -- handles userspace copying for ioctl arguments
- * Obsolete usercopy function - Should be removed soon
- */
-long
-video_usercopy(struct file *file, unsigned int cmd, unsigned long arg,
-		v4l2_kioctl func)
-{
-	char	sbuf[128];
-	void    *mbuf = NULL;
-	void	*parg = NULL;
-	long	err  = -EINVAL;
-	int     is_ext_ctrl;
-	size_t  ctrls_size = 0;
-	void __user *user_ptr = NULL;
-
-	is_ext_ctrl = (cmd == VIDIOC_S_EXT_CTRLS || cmd == VIDIOC_G_EXT_CTRLS ||
-		       cmd == VIDIOC_TRY_EXT_CTRLS);
-
-	/*  Copy arguments into temp kernel buffer  */
-	switch (_IOC_DIR(cmd)) {
-	case _IOC_NONE:
-		parg = NULL;
-		break;
-	case _IOC_READ:
-	case _IOC_WRITE:
-	case (_IOC_WRITE | _IOC_READ):
-		if (_IOC_SIZE(cmd) <= sizeof(sbuf)) {
-			parg = sbuf;
-		} else {
-			/* too big to allocate from stack */
-			mbuf = kmalloc(_IOC_SIZE(cmd), GFP_KERNEL);
-			if (NULL == mbuf)
-				return -ENOMEM;
-			parg = mbuf;
-		}
-
-		err = -EFAULT;
-		if (_IOC_DIR(cmd) & _IOC_WRITE)
-			if (copy_from_user(parg, (void __user *)arg, _IOC_SIZE(cmd)))
-				goto out;
-		break;
-	}
-	if (is_ext_ctrl) {
-		struct v4l2_ext_controls *p = parg;
-
-		/* In case of an error, tell the caller that it wasn't
-		   a specific control that caused it. */
-		p->error_idx = p->count;
-		user_ptr = (void __user *)p->controls;
-		if (p->count) {
-			ctrls_size = sizeof(struct v4l2_ext_control) * p->count;
-			/* Note: v4l2_ext_controls fits in sbuf[] so mbuf is still NULL. */
-			mbuf = kmalloc(ctrls_size, GFP_KERNEL);
-			err = -ENOMEM;
-			if (NULL == mbuf)
-				goto out_ext_ctrl;
-			err = -EFAULT;
-			if (copy_from_user(mbuf, user_ptr, ctrls_size))
-				goto out_ext_ctrl;
-			p->controls = mbuf;
-		}
-	}
-
-	/* call driver */
-	err = func(file, cmd, parg);
-	if (err == -ENOIOCTLCMD)
-		err = -EINVAL;
-	if (is_ext_ctrl) {
-		struct v4l2_ext_controls *p = parg;
-
-		p->controls = (void *)user_ptr;
-		if (p->count && err == 0 && copy_to_user(user_ptr, mbuf, ctrls_size))
-			err = -EFAULT;
-		goto out_ext_ctrl;
-	}
-	if (err < 0)
-		goto out;
-
-out_ext_ctrl:
-	/*  Copy results into user buffer  */
-	switch (_IOC_DIR(cmd)) {
-	case _IOC_READ:
-	case (_IOC_WRITE | _IOC_READ):
-		if (copy_to_user((void __user *)arg, parg, _IOC_SIZE(cmd)))
-			err = -EFAULT;
-		break;
-	}
-
-out:
-	kfree(mbuf);
-	return err;
-}
-EXPORT_SYMBOL(video_usercopy);
-
 static void dbgbuf(unsigned int cmd, struct video_device *vfd,
 					struct v4l2_buffer *p)
 {
@@ -2332,8 +2237,9 @@
 	return ret;
 }
 
-long video_ioctl2(struct file *file,
-	       unsigned int cmd, unsigned long arg)
+long
+video_usercopy(struct file *file, unsigned int cmd, unsigned long arg,
+	       v4l2_kioctl func)
 {
 	char	sbuf[128];
 	void    *mbuf = NULL;
@@ -2395,7 +2301,7 @@
 	}
 
 	/* Handles IOCTL */
-	err = __video_do_ioctl(file, cmd, parg);
+	err = func(file, cmd, parg);
 	if (err == -ENOIOCTLCMD)
 		err = -EINVAL;
 
@@ -2422,4 +2328,11 @@
 	kfree(mbuf);
 	return err;
 }
+EXPORT_SYMBOL(video_usercopy);
+
+long video_ioctl2(struct file *file,
+	       unsigned int cmd, unsigned long arg)
+{
+	return video_usercopy(file, cmd, arg, __video_do_ioctl);
+}
 EXPORT_SYMBOL(video_ioctl2);
```
