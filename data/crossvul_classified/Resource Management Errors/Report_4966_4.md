# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 4966_4
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4966_4`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 99-139 of the vulnerable file.

{
	struct sock *u_sock = NULL;
	struct inode *inode = file_inode(filp);

	/* Socket ? */
	if (S_ISSOCK(inode->i_mode) && !(filp->f_mode & FMODE_PATH)) {
		struct socket *sock = SOCKET_I(inode);
		struct sock *s = sock->sk;

		/* PF_UNIX ? */
		if (s && sock->ops && sock->ops->family == PF_UNIX)
			u_sock = s;
	}
	return u_sock;
}

/* Keep the number of times in flight count for the file
 * descriptor if it is for an AF_UNIX socket.
 */

void unix_inflight(struct file *fp)
{
	struct sock *s = unix_get_socket(fp);

	spin_lock(&unix_gc_lock);

	if (s) {
		struct unix_sock *u = unix_sk(s);

		if (atomic_long_inc_return(&u->inflight) == 1) {
			BUG_ON(!list_empty(&u->link));
			list_add_tail(&u->link, &gc_inflight_list);
		} else {
			BUG_ON(list_empty(&u->link));
		}
		unix_tot_inflight++;
	}
	fp->f_cred->user->unix_inflight++;
	spin_unlock(&unix_gc_lock);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -116,7 +116,7 @@
  * descriptor if it is for an AF_UNIX socket.
  */
 
-void unix_inflight(struct file *fp)
+void unix_inflight(struct user_struct *user, struct file *fp)
 {
 	struct sock *s = unix_get_socket(fp);
 
@@ -133,11 +133,11 @@
 		}
 		unix_tot_inflight++;
 	}
-	fp->f_cred->user->unix_inflight++;
+	user->unix_inflight++;
 	spin_unlock(&unix_gc_lock);
 }
 
-void unix_notinflight(struct file *fp)
+void unix_notinflight(struct user_struct *user, struct file *fp)
 {
 	struct sock *s = unix_get_socket(fp);
 
@@ -152,7 +152,7 @@
 			list_del_init(&u->link);
 		unix_tot_inflight--;
 	}
-	fp->f_cred->user->unix_inflight--;
+	user->unix_inflight--;
 	spin_unlock(&unix_gc_lock);
 }
 
```
