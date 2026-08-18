# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1776_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1776_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 4886-4926 of the vulnerable file.

	loff_t pos = *ppos;
	struct ctl_table lctl;
	int ret;

	/*
	 * ctl->data points to idev->cnf.forwarding, we should
	 * not modify it until we get the rtnl lock.
	 */
	lctl = *ctl;
	lctl.data = &val;

	ret = proc_dointvec(&lctl, write, buffer, lenp, ppos);

	if (write)
		ret = addrconf_fixup_forwarding(ctl, valp, val);
	if (ret)
		*ppos = pos;
	return ret;
}

static void dev_disable_change(struct inet6_dev *idev)
{
	struct netdev_notifier_info info;

	if (!idev || !idev->dev)
		return;

	netdev_notifier_info_init(&info, idev->dev);
	if (idev->cnf.disable_ipv6)
		addrconf_notify(NULL, NETDEV_DOWN, &info);
	else
		addrconf_notify(NULL, NETDEV_UP, &info);
}

static void addrconf_disable_change(struct net *net, __s32 newf)
{
	struct net_device *dev;
	struct inet6_dev *idev;

	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4903,6 +4903,21 @@
 	return ret;
 }
 
+static
+int addrconf_sysctl_mtu(struct ctl_table *ctl, int write,
+			void __user *buffer, size_t *lenp, loff_t *ppos)
+{
+	struct inet6_dev *idev = ctl->extra1;
+	int min_mtu = IPV6_MIN_MTU;
+	struct ctl_table lctl;
+
+	lctl = *ctl;
+	lctl.extra1 = &min_mtu;
+	lctl.extra2 = idev ? &idev->dev->mtu : NULL;
+
+	return proc_dointvec_minmax(&lctl, write, buffer, lenp, ppos);
+}
+
 static void dev_disable_change(struct inet6_dev *idev)
 {
 	struct netdev_notifier_info info;
@@ -5054,7 +5069,7 @@
 			.data		= &ipv6_devconf.mtu6,
 			.maxlen		= sizeof(int),
 			.mode		= 0644,
-			.proc_handler	= proc_dointvec,
+			.proc_handler	= addrconf_sysctl_mtu,
 		},
 		{
 			.procname	= "accept_ra",
```
