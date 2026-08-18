# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 175_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `175_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 524-564 of the vulnerable file.


	len = (XATTR_NAME_SOCKPROTONAME_LEN + 1);
	used += len;
	if (buffer) {
		if (size < used)
			return -ERANGE;
		memcpy(buffer, XATTR_NAME_SOCKPROTONAME, len);
		buffer += len;
	}

	return used;
}

static int sockfs_setattr(struct dentry *dentry, struct iattr *iattr)
{
	int err = simple_setattr(dentry, iattr);

	if (!err && (iattr->ia_valid & ATTR_UID)) {
		struct socket *sock = SOCKET_I(d_inode(dentry));

		sock->sk->sk_uid = iattr->ia_uid;
	}

	return err;
}

static const struct inode_operations sockfs_inode_ops = {
	.listxattr = sockfs_listxattr,
	.setattr = sockfs_setattr,
};

/**
 *	sock_alloc	-	allocate a socket
 *
 *	Allocate a new inode and socket object. The two are bound together
 *	and initialised. The socket is then returned. If we are out of inodes
 *	NULL is returned.
 */

struct socket *sock_alloc(void)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -541,7 +541,10 @@
 	if (!err && (iattr->ia_valid & ATTR_UID)) {
 		struct socket *sock = SOCKET_I(d_inode(dentry));
 
-		sock->sk->sk_uid = iattr->ia_uid;
+		if (sock->sk)
+			sock->sk->sk_uid = iattr->ia_uid;
+		else
+			err = -ENOENT;
 	}
 
 	return err;
@@ -590,12 +593,16 @@
  *	an inode not a file.
  */
 
-void sock_release(struct socket *sock)
+static void __sock_release(struct socket *sock, struct inode *inode)
 {
 	if (sock->ops) {
 		struct module *owner = sock->ops->owner;
 
+		if (inode)
+			inode_lock(inode);
 		sock->ops->release(sock);
+		if (inode)
+			inode_unlock(inode);
 		sock->ops = NULL;
 		module_put(owner);
 	}
@@ -608,6 +615,11 @@
 		return;
 	}
 	sock->file = NULL;
+}
+
+void sock_release(struct socket *sock)
+{
+	__sock_release(sock, NULL);
 }
 EXPORT_SYMBOL(sock_release);
 
@@ -1171,7 +1183,7 @@
 
 static int sock_close(struct inode *inode, struct file *filp)
 {
-	sock_release(SOCKET_I(inode));
+	__sock_release(SOCKET_I(inode), inode);
 	return 0;
 }
 
```
