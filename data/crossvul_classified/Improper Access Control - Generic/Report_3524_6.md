# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3524_6
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3524_6`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1057-1097 of the vulnerable file.

	.ndo_do_ioctl   = pvc_ioctl,
};

static int fr_add_pvc(struct net_device *frad, unsigned int dlci, int type)
{
	hdlc_device *hdlc = dev_to_hdlc(frad);
	pvc_device *pvc;
	struct net_device *dev;
	int used;

	if ((pvc = add_pvc(frad, dlci)) == NULL) {
		netdev_warn(frad, "Memory squeeze on fr_add_pvc()\n");
		return -ENOBUFS;
	}

	if (*get_dev_p(pvc, type))
		return -EEXIST;

	used = pvc_is_used(pvc);

	if (type == ARPHRD_ETHER)
		dev = alloc_netdev(0, "pvceth%d", ether_setup);
	else
		dev = alloc_netdev(0, "pvc%d", pvc_setup);

	if (!dev) {
		netdev_warn(frad, "Memory squeeze on fr_pvc()\n");
		delete_unused_pvcs(hdlc);
		return -ENOBUFS;
	}

	if (type == ARPHRD_ETHER)
		random_ether_addr(dev->dev_addr);
	else {
		*(__be16*)dev->dev_addr = htons(dlci);
		dlci_to_q922(dev->broadcast, dlci);
	}
	dev->netdev_ops = &pvc_ops;
	dev->mtu = HDLC_MAX_MTU;
	dev->tx_queue_len = 0;
	dev->ml_priv = pvc;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1074,9 +1074,10 @@
 
 	used = pvc_is_used(pvc);
 
-	if (type == ARPHRD_ETHER)
+	if (type == ARPHRD_ETHER) {
 		dev = alloc_netdev(0, "pvceth%d", ether_setup);
-	else
+		dev->priv_flags &= ~IFF_TX_SKB_SHARING;
+	} else
 		dev = alloc_netdev(0, "pvc%d", pvc_setup);
 
 	if (!dev) {
```
