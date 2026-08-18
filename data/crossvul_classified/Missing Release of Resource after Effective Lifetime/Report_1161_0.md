# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 1161_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1161_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 1856-1896 of the vulnerable file.

	sitn->fb_tunnel_dev->rtnl_link_ops = &sit_link_ops;
	/* FB netdevice is special: we have one, and only one per netns.
	 * Allowing to move it to another netns is clearly unsafe.
	 */
	sitn->fb_tunnel_dev->features |= NETIF_F_NETNS_LOCAL;

	err = register_netdev(sitn->fb_tunnel_dev);
	if (err)
		goto err_reg_dev;

	ipip6_tunnel_clone_6rd(sitn->fb_tunnel_dev, sitn);
	ipip6_fb_tunnel_init(sitn->fb_tunnel_dev);

	t = netdev_priv(sitn->fb_tunnel_dev);

	strcpy(t->parms.name, sitn->fb_tunnel_dev->name);
	return 0;

err_reg_dev:
	ipip6_dev_free(sitn->fb_tunnel_dev);
err_alloc_dev:
	return err;
}

static void __net_exit sit_exit_batch_net(struct list_head *net_list)
{
	LIST_HEAD(list);
	struct net *net;

	rtnl_lock();
	list_for_each_entry(net, net_list, exit_list)
		sit_destroy_tunnels(net, &list);

	unregister_netdevice_many(&list);
	rtnl_unlock();
}

static struct pernet_operations sit_net_ops = {
	.init = sit_init_net,
	.exit_batch = sit_exit_batch_net,
	.id   = &sit_net_id,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1873,6 +1873,7 @@
 
 err_reg_dev:
 	ipip6_dev_free(sitn->fb_tunnel_dev);
+	free_netdev(sitn->fb_tunnel_dev);
 err_alloc_dev:
 	return err;
 }
```
