# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3141_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3141_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1074-1115 of the vulnerable file.

		return err;
	}
	default:
		return -EINVAL;
	}

out_unlock0:
	ipc_unlock_object(&shp->shm_perm);
out_unlock1:
	rcu_read_unlock();
	return err;
}

/*
 * Fix shmaddr, allocate descriptor, map shm, add attach descriptor to lists.
 *
 * NOTE! Despite the name, this is NOT a direct system call entrypoint. The
 * "raddr" thing points to kernel space, and there has to be a wrapper around
 * this.
 */
long do_shmat(int shmid, char __user *shmaddr, int shmflg, ulong *raddr,
	      unsigned long shmlba)
{
	struct shmid_kernel *shp;
	unsigned long addr;
	unsigned long size;
	struct file *file;
	int    err;
	unsigned long flags;
	unsigned long prot;
	int acc_mode;
	struct ipc_namespace *ns;
	struct shm_file_data *sfd;
	struct path path;
	fmode_t f_mode;
	unsigned long populate = 0;

	err = -EINVAL;
	if (shmid < 0)
		goto out;
	else if ((addr = (ulong)shmaddr)) {
		if (addr & (shmlba - 1)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1091,8 +1091,8 @@
  * "raddr" thing points to kernel space, and there has to be a wrapper around
  * this.
  */
-long do_shmat(int shmid, char __user *shmaddr, int shmflg, ulong *raddr,
-	      unsigned long shmlba)
+long do_shmat(int shmid, char __user *shmaddr, int shmflg,
+	      ulong *raddr, unsigned long shmlba)
 {
 	struct shmid_kernel *shp;
 	unsigned long addr;
@@ -1113,8 +1113,13 @@
 		goto out;
 	else if ((addr = (ulong)shmaddr)) {
 		if (addr & (shmlba - 1)) {
-			if (shmflg & SHM_RND)
-				addr &= ~(shmlba - 1);	   /* round down */
+			/*
+			 * Round down to the nearest multiple of shmlba.
+			 * For sane do_mmap_pgoff() parameters, avoid
+			 * round downs that trigger nil-page and MAP_FIXED.
+			 */
+			if ((shmflg & SHM_RND) && addr >= shmlba)
+				addr &= ~(shmlba - 1);
 			else
 #ifndef __ARCH_FORCE_SHMLBA
 				if (addr & ~PAGE_MASK)
```
