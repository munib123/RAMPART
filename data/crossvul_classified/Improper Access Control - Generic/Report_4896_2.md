# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 4896_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4896_2`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 753-795 of the vulnerable file.


__be32
nfsd4_set_nfs4_acl(struct svc_rqst *rqstp, struct svc_fh *fhp,
		struct nfs4_acl *acl)
{
	__be32 error;
	int host_error;
	struct dentry *dentry;
	struct inode *inode;
	struct posix_acl *pacl = NULL, *dpacl = NULL;
	unsigned int flags = 0;

	/* Get inode */
	error = fh_verify(rqstp, fhp, 0, NFSD_MAY_SATTR);
	if (error)
		return error;

	dentry = fhp->fh_dentry;
	inode = d_inode(dentry);

	if (!inode->i_op->set_acl || !IS_POSIXACL(inode))
		return nfserr_attrnotsupp;

	if (S_ISDIR(inode->i_mode))
		flags = NFS4_ACL_DIR;

	host_error = nfs4_acl_nfsv4_to_posix(acl, &pacl, &dpacl, flags);
	if (host_error == -EINVAL)
		return nfserr_attrnotsupp;
	if (host_error < 0)
		goto out_nfserr;

	host_error = inode->i_op->set_acl(inode, pacl, ACL_TYPE_ACCESS);
	if (host_error < 0)
		goto out_release;

	if (S_ISDIR(inode->i_mode)) {
		host_error = inode->i_op->set_acl(inode, dpacl,
						  ACL_TYPE_DEFAULT);
	}

out_release:
	posix_acl_release(pacl);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -770,9 +770,6 @@
 	dentry = fhp->fh_dentry;
 	inode = d_inode(dentry);
 
-	if (!inode->i_op->set_acl || !IS_POSIXACL(inode))
-		return nfserr_attrnotsupp;
-
 	if (S_ISDIR(inode->i_mode))
 		flags = NFS4_ACL_DIR;
 
@@ -782,16 +779,19 @@
 	if (host_error < 0)
 		goto out_nfserr;
 
-	host_error = inode->i_op->set_acl(inode, pacl, ACL_TYPE_ACCESS);
+	fh_lock(fhp);
+
+	host_error = set_posix_acl(inode, ACL_TYPE_ACCESS, pacl);
 	if (host_error < 0)
-		goto out_release;
+		goto out_drop_lock;
 
 	if (S_ISDIR(inode->i_mode)) {
-		host_error = inode->i_op->set_acl(inode, dpacl,
-						  ACL_TYPE_DEFAULT);
-	}
-
-out_release:
+		host_error = set_posix_acl(inode, ACL_TYPE_DEFAULT, dpacl);
+	}
+
+out_drop_lock:
+	fh_unlock(fhp);
+
 	posix_acl_release(pacl);
 	posix_acl_release(dpacl);
 out_nfserr:
```
