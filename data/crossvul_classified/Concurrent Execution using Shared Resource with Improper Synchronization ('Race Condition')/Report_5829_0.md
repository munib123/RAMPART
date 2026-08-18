# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5829_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5829_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 191-231 of the vulnerable file.


	shp = shm_lock(sfd->ns, sfd->id);
	BUG_ON(IS_ERR(shp));
	shp->shm_atim = get_seconds();
	shp->shm_lprid = task_tgid_vnr(current);
	shp->shm_nattch++;
	shm_unlock(shp);
}

/*
 * shm_destroy - free the struct shmid_kernel
 *
 * @ns: namespace
 * @shp: struct to free
 *
 * It has to be called with shp and shm_ids.rwsem (writer) locked,
 * but returns with shp unlocked and freed.
 */
static void shm_destroy(struct ipc_namespace *ns, struct shmid_kernel *shp)
{
	ns->shm_tot -= (shp->shm_segsz + PAGE_SIZE - 1) >> PAGE_SHIFT;
	shm_rmid(ns, shp);
	shm_unlock(shp);
	if (!is_file_hugepages(shp->shm_file))
		shmem_lock(shp->shm_file, 0, shp->mlock_user);
	else if (shp->mlock_user)
		user_shm_unlock(file_inode(shp->shm_file)->i_size,
						shp->mlock_user);
	fput (shp->shm_file);
	ipc_rcu_putref(shp, shm_rcu_free);
}

/*
 * shm_may_destroy - identifies whether shm segment should be destroyed now
 *
 * Returns true if and only if there are no active users of the segment and
 * one of the following is true:
 *
 * 1) shmctl(id, IPC_RMID, NULL) was called for this shp
 *
 * 2) sysctl kernel.shm_rmid_forced is set to 1.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -208,15 +208,18 @@
  */
 static void shm_destroy(struct ipc_namespace *ns, struct shmid_kernel *shp)
 {
+	struct file *shm_file;
+
+	shm_file = shp->shm_file;
+	shp->shm_file = NULL;
 	ns->shm_tot -= (shp->shm_segsz + PAGE_SIZE - 1) >> PAGE_SHIFT;
 	shm_rmid(ns, shp);
 	shm_unlock(shp);
-	if (!is_file_hugepages(shp->shm_file))
-		shmem_lock(shp->shm_file, 0, shp->mlock_user);
+	if (!is_file_hugepages(shm_file))
+		shmem_lock(shm_file, 0, shp->mlock_user);
 	else if (shp->mlock_user)
-		user_shm_unlock(file_inode(shp->shm_file)->i_size,
-						shp->mlock_user);
-	fput (shp->shm_file);
+		user_shm_unlock(file_inode(shm_file)->i_size, shp->mlock_user);
+	fput(shm_file);
 	ipc_rcu_putref(shp, shm_rcu_free);
 }
 
@@ -983,6 +986,13 @@
 		}
 
 		shm_file = shp->shm_file;
+
+		/* check if shm_destroy() is tearing down shp */
+		if (shm_file == NULL) {
+			err = -EIDRM;
+			goto out_unlock0;
+		}
+
 		if (is_file_hugepages(shm_file))
 			goto out_unlock0;
 
@@ -1101,6 +1111,14 @@
 		goto out_unlock;
 
 	ipc_lock_object(&shp->shm_perm);
+
+	/* check if shm_destroy() is tearing down shp */
+	if (shp->shm_file == NULL) {
+		ipc_unlock_object(&shp->shm_perm);
+		err = -EIDRM;
+		goto out_unlock;
+	}
+
 	path = shp->shm_file->f_path;
 	path_get(&path);
 	shp->shm_nattch++;
```
