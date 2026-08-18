# CrossVul Fix Pair: Double Free in c
**Pair ID:** 5504_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5504_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 2042-2082 of the vulnerable file.

	nlh->nlmsg_flags = flags;
	nlh->nlmsg_pid = portid;
	nlh->nlmsg_seq = seq;
	if (!__builtin_constant_p(size) || NLMSG_ALIGN(size) - size != 0)
		memset(nlmsg_data(nlh) + len, 0, NLMSG_ALIGN(size) - size);
	return nlh;
}
EXPORT_SYMBOL(__nlmsg_put);

/*
 * It looks a bit ugly.
 * It would be better to create kernel thread.
 */

static int netlink_dump(struct sock *sk)
{
	struct netlink_sock *nlk = nlk_sk(sk);
	struct netlink_callback *cb;
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh;
	int len, err = -ENOBUFS;
	int alloc_min_size;
	int alloc_size;

	mutex_lock(nlk->cb_mutex);
	if (!nlk->cb_running) {
		err = -EINVAL;
		goto errout_skb;
	}

	if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf)
		goto errout_skb;

	/* NLMSG_GOODSIZE is small to avoid high order allocations being
	 * required, but it makes sense to _attempt_ a 16K bytes allocation
	 * to reduce number of system calls on dump operations, if user
	 * ever provided a big enough buffer.
	 */
	cb = &nlk->cb;
	alloc_min_size = max_t(int, cb->min_dump_alloc, NLMSG_GOODSIZE);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2059,6 +2059,7 @@
 	struct netlink_callback *cb;
 	struct sk_buff *skb = NULL;
 	struct nlmsghdr *nlh;
+	struct module *module;
 	int len, err = -ENOBUFS;
 	int alloc_min_size;
 	int alloc_size;
@@ -2134,9 +2135,11 @@
 		cb->done(cb);
 
 	nlk->cb_running = false;
+	module = cb->module;
+	skb = cb->skb;
 	mutex_unlock(nlk->cb_mutex);
-	module_put(cb->module);
-	consume_skb(cb->skb);
+	module_put(module);
+	consume_skb(skb);
 	return 0;
 
 errout_skb:
```
