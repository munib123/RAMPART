# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3459_2
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3459_2`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1210-1245 of the vulnerable file.

	.init = sit_init_net,
	.exit = sit_exit_net,
	.id   = &sit_net_id,
	.size = sizeof(struct sit_net),
};

static void __exit sit_cleanup(void)
{
	xfrm4_tunnel_deregister(&sit_handler, AF_INET6);

	unregister_pernet_device(&sit_net_ops);
	rcu_barrier(); /* Wait for completion of call_rcu()'s */
}

static int __init sit_init(void)
{
	int err;

	printk(KERN_INFO "IPv6 over IPv4 tunneling driver\n");

	if (xfrm4_tunnel_register(&sit_handler, AF_INET6) < 0) {
		printk(KERN_INFO "sit init: Can't add protocol\n");
		return -EAGAIN;
	}

	err = register_pernet_device(&sit_net_ops);
	if (err < 0)
		xfrm4_tunnel_deregister(&sit_handler, AF_INET6);

	return err;
}

module_init(sit_init);
module_exit(sit_cleanup);
MODULE_LICENSE("GPL");
MODULE_ALIAS("sit0");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1227,15 +1227,14 @@
 
 	printk(KERN_INFO "IPv6 over IPv4 tunneling driver\n");
 
-	if (xfrm4_tunnel_register(&sit_handler, AF_INET6) < 0) {
-		printk(KERN_INFO "sit init: Can't add protocol\n");
-		return -EAGAIN;
-	}
-
 	err = register_pernet_device(&sit_net_ops);
 	if (err < 0)
-		xfrm4_tunnel_deregister(&sit_handler, AF_INET6);
-
+		return err;
+	err = xfrm4_tunnel_register(&sit_handler, AF_INET6);
+	if (err < 0) {
+		unregister_pernet_device(&sit_net_ops);
+		printk(KERN_INFO "sit init: Can't add protocol\n");
+	}
 	return err;
 }
 
```
