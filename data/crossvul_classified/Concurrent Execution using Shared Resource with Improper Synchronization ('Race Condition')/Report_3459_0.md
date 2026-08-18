# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3459_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3459_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 813-853 of the vulnerable file.

	rtnl_lock();
	ipip_destroy_tunnels(ipn, &list);
	unregister_netdevice_queue(ipn->fb_tunnel_dev, &list);
	unregister_netdevice_many(&list);
	rtnl_unlock();
}

static struct pernet_operations ipip_net_ops = {
	.init = ipip_init_net,
	.exit = ipip_exit_net,
	.id   = &ipip_net_id,
	.size = sizeof(struct ipip_net),
};

static int __init ipip_init(void)
{
	int err;

	printk(banner);

	if (xfrm4_tunnel_register(&ipip_handler, AF_INET)) {
		printk(KERN_INFO "ipip init: can't register tunnel\n");
		return -EAGAIN;
	}

	err = register_pernet_device(&ipip_net_ops);
	if (err)
		xfrm4_tunnel_deregister(&ipip_handler, AF_INET);

	return err;
}

static void __exit ipip_fini(void)
{
	if (xfrm4_tunnel_deregister(&ipip_handler, AF_INET))
		printk(KERN_INFO "ipip close: can't deregister tunnel\n");

	unregister_pernet_device(&ipip_net_ops);
}

module_init(ipip_init);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -830,15 +830,14 @@
 
 	printk(banner);
 
-	if (xfrm4_tunnel_register(&ipip_handler, AF_INET)) {
+	err = register_pernet_device(&ipip_net_ops);
+	if (err < 0)
+		return err;
+	err = xfrm4_tunnel_register(&ipip_handler, AF_INET);
+	if (err < 0) {
+		unregister_pernet_device(&ipip_net_ops);
 		printk(KERN_INFO "ipip init: can't register tunnel\n");
-		return -EAGAIN;
-	}
-
-	err = register_pernet_device(&ipip_net_ops);
-	if (err)
-		xfrm4_tunnel_deregister(&ipip_handler, AF_INET);
-
+	}
 	return err;
 }
 
```
