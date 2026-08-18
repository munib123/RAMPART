# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3447_3
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3447_3`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 803-843 of the vulnerable file.

		opl3_command(devc->right_io, CONNECTION_SELECT_REGISTER, devc->cmask);
	return 0;
}

static void opl3_close(int dev)
{
	devc->busy = 0;
	devc->v_alloc->max_voice = devc->nr_voice = (devc->model == 2) ? 18 : 9;

	devc->fm_info.nr_drums = 0;
	devc->fm_info.perc_mode = 0;

	opl3_reset(dev);
}

static void opl3_hw_control(int dev, unsigned char *event)
{
}

static int opl3_load_patch(int dev, int format, const char __user *addr,
		int offs, int count, int pmgr_flag)
{
	struct sbi_instrument ins;

	if (count <sizeof(ins))
	{
		printk(KERN_WARNING "FM Error: Patch record too short\n");
		return -EINVAL;
	}

	/*
	 * What the fuck is going on here?  We leave junk in the beginning
	 * of ins and then check the field pretty close to that beginning?
	 */
	if(copy_from_user(&((char *) &ins)[offs], addr + offs, sizeof(ins) - offs))
		return -EFAULT;

	if (ins.channel < 0 || ins.channel >= SBFM_MAXINSTR)
	{
		printk(KERN_WARNING "FM Error: Invalid instrument number %d\n", ins.channel);
		return -EINVAL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -820,7 +820,7 @@
 }
 
 static int opl3_load_patch(int dev, int format, const char __user *addr,
-		int offs, int count, int pmgr_flag)
+		int count, int pmgr_flag)
 {
 	struct sbi_instrument ins;
 
@@ -830,11 +830,7 @@
 		return -EINVAL;
 	}
 
-	/*
-	 * What the fuck is going on here?  We leave junk in the beginning
-	 * of ins and then check the field pretty close to that beginning?
-	 */
-	if(copy_from_user(&((char *) &ins)[offs], addr + offs, sizeof(ins) - offs))
+	if (copy_from_user(&ins, addr, sizeof(ins)))
 		return -EFAULT;
 
 	if (ins.channel < 0 || ins.channel >= SBFM_MAXINSTR)
```
