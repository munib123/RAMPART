# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1595_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1595_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1258-1298 of the vulnerable file.

	if (task_no_new_privs(current))
		bprm->unsafe |= LSM_UNSAFE_NO_NEW_PRIVS;

	t = p;
	n_fs = 1;
	spin_lock(&p->fs->lock);
	rcu_read_lock();
	while_each_thread(p, t) {
		if (t->fs == p->fs)
			n_fs++;
	}
	rcu_read_unlock();

	if (p->fs->users > n_fs)
		bprm->unsafe |= LSM_UNSAFE_SHARE;
	else
		p->fs->in_exec = 1;
	spin_unlock(&p->fs->lock);
}

/*
 * Fill the binprm structure from the inode.
 * Check permissions, then read the first 128 (BINPRM_BUF_SIZE) bytes
 *
 * This may be called multiple times for binary chains (scripts for example).
 */
int prepare_binprm(struct linux_binprm *bprm)
{
	struct inode *inode = file_inode(bprm->file);
	umode_t mode = inode->i_mode;
	int retval;


	/* clear any previous set[ug]id data from a previous binary */
	bprm->cred->euid = current_euid();
	bprm->cred->egid = current_egid();

	if (!(bprm->file->f_path.mnt->mnt_flags & MNT_NOSUID) &&
	    !task_no_new_privs(current) &&
	    kuid_has_mapping(bprm->cred->user_ns, inode->i_uid) &&
	    kgid_has_mapping(bprm->cred->user_ns, inode->i_gid)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1275,6 +1275,53 @@
 	spin_unlock(&p->fs->lock);
 }
 
+static void bprm_fill_uid(struct linux_binprm *bprm)
+{
+	struct inode *inode;
+	unsigned int mode;
+	kuid_t uid;
+	kgid_t gid;
+
+	/* clear any previous set[ug]id data from a previous binary */
+	bprm->cred->euid = current_euid();
+	bprm->cred->egid = current_egid();
+
+	if (bprm->file->f_path.mnt->mnt_flags & MNT_NOSUID)
+		return;
+
+	if (task_no_new_privs(current))
+		return;
+
+	inode = file_inode(bprm->file);
+	mode = READ_ONCE(inode->i_mode);
+	if (!(mode & (S_ISUID|S_ISGID)))
+		return;
+
+	/* Be careful if suid/sgid is set */
+	mutex_lock(&inode->i_mutex);
+
+	/* reload atomically mode/uid/gid now that lock held */
+	mode = inode->i_mode;
+	uid = inode->i_uid;
+	gid = inode->i_gid;
+	mutex_unlock(&inode->i_mutex);
+
+	/* We ignore suid/sgid if there are no mappings for them in the ns */
+	if (!kuid_has_mapping(bprm->cred->user_ns, uid) ||
+		 !kgid_has_mapping(bprm->cred->user_ns, gid))
+		return;
+
+	if (mode & S_ISUID) {
+		bprm->per_clear |= PER_CLEAR_ON_SETID;
+		bprm->cred->euid = uid;
+	}
+
+	if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
+		bprm->per_clear |= PER_CLEAR_ON_SETID;
+		bprm->cred->egid = gid;
+	}
+}
+
 /*
  * Fill the binprm structure from the inode.
  * Check permissions, then read the first 128 (BINPRM_BUF_SIZE) bytes
@@ -1283,36 +1330,9 @@
  */
 int prepare_binprm(struct linux_binprm *bprm)
 {
-	struct inode *inode = file_inode(bprm->file);
-	umode_t mode = inode->i_mode;
 	int retval;
 
-
-	/* clear any previous set[ug]id data from a previous binary */
-	bprm->cred->euid = current_euid();
-	bprm->cred->egid = current_egid();
-
-	if (!(bprm->file->f_path.mnt->mnt_flags & MNT_NOSUID) &&
-	    !task_no_new_privs(current) &&
-	    kuid_has_mapping(bprm->cred->user_ns, inode->i_uid) &&
-	    kgid_has_mapping(bprm->cred->user_ns, inode->i_gid)) {
-		/* Set-uid? */
-		if (mode & S_ISUID) {
-			bprm->per_clear |= PER_CLEAR_ON_SETID;
-			bprm->cred->euid = inode->i_uid;
-		}
-
-		/* Set-gid? */
-		/*
-		 * If setgid is set but no group execute bit then this
-		 * is a candidate for mandatory locking, not a setgid
-		 * executable.
-		 */
-		if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
-			bprm->per_clear |= PER_CLEAR_ON_SETID;
-			bprm->cred->egid = inode->i_gid;
-		}
-	}
+	bprm_fill_uid(bprm);
 
 	/* fill in binprm security blob */
 	retval = security_bprm_set_creds(bprm);
```
