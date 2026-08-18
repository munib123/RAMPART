# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3459_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3459_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1444-1484 of the vulnerable file.

	rtnl_unlock();
}

static struct pernet_operations ip6_tnl_net_ops = {
	.init = ip6_tnl_init_net,
	.exit = ip6_tnl_exit_net,
	.id   = &ip6_tnl_net_id,
	.size = sizeof(struct ip6_tnl_net),
};

/**
 * ip6_tunnel_init - register protocol and reserve needed resources
 *
 * Return: 0 on success
 **/

static int __init ip6_tunnel_init(void)
{
	int  err;

	if (xfrm6_tunnel_register(&ip4ip6_handler, AF_INET)) {
		printk(KERN_ERR "ip6_tunnel init: can't register ip4ip6\n");
		err = -EAGAIN;
		goto out;
	}

	if (xfrm6_tunnel_register(&ip6ip6_handler, AF_INET6)) {
		printk(KERN_ERR "ip6_tunnel init: can't register ip6ip6\n");
		err = -EAGAIN;
		goto unreg_ip4ip6;
	}

	err = register_pernet_device(&ip6_tnl_net_ops);
	if (err < 0)
		goto err_pernet;
	return 0;
err_pernet:
	xfrm6_tunnel_deregister(&ip6ip6_handler, AF_INET6);
unreg_ip4ip6:
	xfrm6_tunnel_deregister(&ip4ip6_handler, AF_INET);
out:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1461,27 +1461,29 @@
 {
 	int  err;
 
-	if (xfrm6_tunnel_register(&ip4ip6_handler, AF_INET)) {
-		printk(KERN_ERR "ip6_tunnel init: can't register ip4ip6\n");
-		err = -EAGAIN;
-		goto out;
-	}
-
-	if (xfrm6_tunnel_register(&ip6ip6_handler, AF_INET6)) {
-		printk(KERN_ERR "ip6_tunnel init: can't register ip6ip6\n");
-		err = -EAGAIN;
-		goto unreg_ip4ip6;
-	}
-
 	err = register_pernet_device(&ip6_tnl_net_ops);
 	if (err < 0)
-		goto err_pernet;
+		goto out_pernet;
+
+	err = xfrm6_tunnel_register(&ip4ip6_handler, AF_INET);
+	if (err < 0) {
+		printk(KERN_ERR "ip6_tunnel init: can't register ip4ip6\n");
+		goto out_ip4ip6;
+	}
+
+	err = xfrm6_tunnel_register(&ip6ip6_handler, AF_INET6);
+	if (err < 0) {
+		printk(KERN_ERR "ip6_tunnel init: can't register ip6ip6\n");
+		goto out_ip6ip6;
+	}
+
 	return 0;
-err_pernet:
-	xfrm6_tunnel_deregister(&ip6ip6_handler, AF_INET6);
-unreg_ip4ip6:
+
+out_ip6ip6:
 	xfrm6_tunnel_deregister(&ip4ip6_handler, AF_INET);
-out:
+out_ip4ip6:
+	unregister_pernet_device(&ip6_tnl_net_ops);
+out_pernet:
 	return err;
 }
 
```
