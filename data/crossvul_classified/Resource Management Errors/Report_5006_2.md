# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5006_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5006_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 91-131 of the vulnerable file.

	struct net *net = dev_net(dev);

	if (event == NETDEV_DOWN) {
		/* Device was downed.  Search entire table for
		 * conntracks which were associated with that device,
		 * and forget them.
		 */
		NF_CT_ASSERT(dev->ifindex != 0);

		nf_ct_iterate_cleanup(net, device_cmp,
				      (void *)(long)dev->ifindex, 0, 0);
	}

	return NOTIFY_DONE;
}

static int masq_inet_event(struct notifier_block *this,
			   unsigned long event,
			   void *ptr)
{
	struct net_device *dev = ((struct in_ifaddr *)ptr)->ifa_dev->dev;
	struct netdev_notifier_info info;

	netdev_notifier_info_init(&info, dev);
	return masq_device_event(this, event, &info);
}

static struct notifier_block masq_dev_notifier = {
	.notifier_call	= masq_device_event,
};

static struct notifier_block masq_inet_notifier = {
	.notifier_call	= masq_inet_event,
};

static atomic_t masquerade_notifier_refcount = ATOMIC_INIT(0);

void nf_nat_masquerade_ipv4_register_notifier(void)
{
	/* check if the notifier was already set */
	if (atomic_inc_return(&masquerade_notifier_refcount) > 1)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -108,10 +108,18 @@
 			   unsigned long event,
 			   void *ptr)
 {
-	struct net_device *dev = ((struct in_ifaddr *)ptr)->ifa_dev->dev;
+	struct in_device *idev = ((struct in_ifaddr *)ptr)->ifa_dev;
 	struct netdev_notifier_info info;
 
-	netdev_notifier_info_init(&info, dev);
+	/* The masq_dev_notifier will catch the case of the device going
+	 * down.  So if the inetdev is dead and being destroyed we have
+	 * no work to do.  Otherwise this is an individual address removal
+	 * and we have to perform the flush.
+	 */
+	if (idev->dead)
+		return NOTIFY_DONE;
+
+	netdev_notifier_info_init(&info, idev->dev);
 	return masq_device_event(this, event, &info);
 }
 
```
