# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5740_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5740_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 103-143 of the vulnerable file.

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

	if (s) {
		struct unix_sock *u = unix_sk(s);

		spin_lock(&unix_gc_lock);

		if (atomic_long_inc_return(&u->inflight) == 1) {
			BUG_ON(!list_empty(&u->link));
			list_add_tail(&u->link, &gc_inflight_list);
		} else {
			BUG_ON(list_empty(&u->link));
		}
		unix_tot_inflight++;
		spin_unlock(&unix_gc_lock);
	}
}

void unix_notinflight(struct file *fp)
{
	struct sock *s = unix_get_socket(fp);

	if (s) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -120,10 +120,10 @@
 {
 	struct sock *s = unix_get_socket(fp);
 
+	spin_lock(&unix_gc_lock);
+
 	if (s) {
 		struct unix_sock *u = unix_sk(s);
-
-		spin_lock(&unix_gc_lock);
 
 		if (atomic_long_inc_return(&u->inflight) == 1) {
 			BUG_ON(!list_empty(&u->link));
@@ -132,25 +132,28 @@
 			BUG_ON(list_empty(&u->link));
 		}
 		unix_tot_inflight++;
-		spin_unlock(&unix_gc_lock);
-	}
+	}
+	fp->f_cred->user->unix_inflight++;
+	spin_unlock(&unix_gc_lock);
 }
 
 void unix_notinflight(struct file *fp)
 {
 	struct sock *s = unix_get_socket(fp);
+
+	spin_lock(&unix_gc_lock);
 
 	if (s) {
 		struct unix_sock *u = unix_sk(s);
 
-		spin_lock(&unix_gc_lock);
 		BUG_ON(list_empty(&u->link));
 
 		if (atomic_long_dec_and_test(&u->inflight))
 			list_del_init(&u->link);
 		unix_tot_inflight--;
-		spin_unlock(&unix_gc_lock);
-	}
+	}
+	fp->f_cred->user->unix_inflight--;
+	spin_unlock(&unix_gc_lock);
 }
 
 static void scan_inflight(struct sock *x, void (*func)(struct unix_sock *),
```
