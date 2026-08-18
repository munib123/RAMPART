# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 4896_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4896_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 78-121 of the vulnerable file.

}

/*
 * Set the Access and/or Default ACL of a file.
 */
static __be32 nfsd3_proc_setacl(struct svc_rqst * rqstp,
		struct nfsd3_setaclargs *argp,
		struct nfsd3_attrstat *resp)
{
	struct inode *inode;
	svc_fh *fh;
	__be32 nfserr = 0;
	int error;

	fh = fh_copy(&resp->fh, &argp->fh);
	nfserr = fh_verify(rqstp, &resp->fh, 0, NFSD_MAY_SATTR);
	if (nfserr)
		goto out;

	inode = d_inode(fh->fh_dentry);
	if (!IS_POSIXACL(inode) || !inode->i_op->set_acl) {
		error = -EOPNOTSUPP;
		goto out_errno;
	}

	error = fh_want_write(fh);
	if (error)
		goto out_errno;

	error = inode->i_op->set_acl(inode, argp->acl_access, ACL_TYPE_ACCESS);
	if (error)
		goto out_drop_write;
	error = inode->i_op->set_acl(inode, argp->acl_default,
				     ACL_TYPE_DEFAULT);

out_drop_write:
	fh_drop_write(fh);
out_errno:
	nfserr = nfserrno(error);
out:
	/* argp->acl_{access,default} may have been allocated in
	   nfs3svc_decode_setaclargs. */
	posix_acl_release(argp->acl_access);
	posix_acl_release(argp->acl_default);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,22 +95,20 @@
 		goto out;
 
 	inode = d_inode(fh->fh_dentry);
-	if (!IS_POSIXACL(inode) || !inode->i_op->set_acl) {
-		error = -EOPNOTSUPP;
-		goto out_errno;
-	}
 
 	error = fh_want_write(fh);
 	if (error)
 		goto out_errno;
 
-	error = inode->i_op->set_acl(inode, argp->acl_access, ACL_TYPE_ACCESS);
+	fh_lock(fh);
+
+	error = set_posix_acl(inode, ACL_TYPE_ACCESS, argp->acl_access);
 	if (error)
-		goto out_drop_write;
-	error = inode->i_op->set_acl(inode, argp->acl_default,
-				     ACL_TYPE_DEFAULT);
-
-out_drop_write:
+		goto out_drop_lock;
+	error = set_posix_acl(inode, ACL_TYPE_DEFAULT, argp->acl_default);
+
+out_drop_lock:
+	fh_unlock(fh);
 	fh_drop_write(fh);
 out_errno:
 	nfserr = nfserrno(error);
```
