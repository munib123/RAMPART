# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3438_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3438_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1097-1137 of the vulnerable file.


int netdev_bonding_change(struct net_device *dev, unsigned long event)
{
	return call_netdevice_notifiers(event, dev);
}
EXPORT_SYMBOL(netdev_bonding_change);

/**
 *	dev_load 	- load a network module
 *	@net: the applicable net namespace
 *	@name: name of interface
 *
 *	If a network interface is not present and the process has suitable
 *	privileges this function loads the module. If module loading is not
 *	available in this kernel then it becomes a nop.
 */

void dev_load(struct net *net, const char *name)
{
	struct net_device *dev;

	rcu_read_lock();
	dev = dev_get_by_name_rcu(net, name);
	rcu_read_unlock();

	if (!dev && capable(CAP_NET_ADMIN))
		request_module("%s", name);
}
EXPORT_SYMBOL(dev_load);

static int __dev_open(struct net_device *dev)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	int ret;

	ASSERT_RTNL();

	/*
	 *	Is it even present?
	 */
	if (!netif_device_present(dev))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1114,13 +1114,21 @@
 void dev_load(struct net *net, const char *name)
 {
 	struct net_device *dev;
+	int no_module;
 
 	rcu_read_lock();
 	dev = dev_get_by_name_rcu(net, name);
 	rcu_read_unlock();
 
-	if (!dev && capable(CAP_NET_ADMIN))
-		request_module("%s", name);
+	no_module = !dev;
+	if (no_module && capable(CAP_NET_ADMIN))
+		no_module = request_module("netdev-%s", name);
+	if (no_module && capable(CAP_SYS_MODULE)) {
+		if (!request_module("%s", name))
+			pr_err("Loading kernel module for a network device "
+"with CAP_SYS_MODULE (deprecated).  Use CAP_NET_ADMIN and alias netdev-%s "
+"instead\n", name);
+	}
 }
 EXPORT_SYMBOL(dev_load);
 
```
