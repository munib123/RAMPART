# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3524_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3524_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 2515-2555 of the vulnerable file.

	.ndo_open	      = isdn_net_open,
	.ndo_stop	      = isdn_net_close,
	.ndo_do_ioctl	      = isdn_net_ioctl,

	.ndo_start_xmit	      = isdn_net_start_xmit,
	.ndo_get_stats	      = isdn_net_get_stats,
	.ndo_tx_timeout	      = isdn_net_tx_timeout,
};

/*
 * Helper for alloc_netdev()
 */
static void _isdn_setup(struct net_device *dev)
{
	isdn_net_local *lp = netdev_priv(dev);

	ether_setup(dev);

	/* Setup the generic properties */
	dev->flags = IFF_NOARP|IFF_POINTOPOINT;
	dev->header_ops = NULL;
	dev->netdev_ops = &isdn_netdev_ops;

	/* for clients with MPPP maybe higher values better */
	dev->tx_queue_len = 30;

	lp->p_encap = ISDN_NET_ENCAP_RAWIP;
	lp->magic = ISDN_NET_MAGIC;
	lp->last = lp;
	lp->next = lp;
	lp->isdn_device = -1;
	lp->isdn_channel = -1;
	lp->pre_device = -1;
	lp->pre_channel = -1;
	lp->exclusive = -1;
	lp->ppp_slot = -1;
	lp->pppbind = -1;
	skb_queue_head_init(&lp->super_tx_queue);
	lp->l2_proto = ISDN_PROTO_L2_X75I;
	lp->l3_proto = ISDN_PROTO_L3_TRANS;
	lp->triggercps = 6000;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2532,6 +2532,9 @@
 
 	/* Setup the generic properties */
 	dev->flags = IFF_NOARP|IFF_POINTOPOINT;
+
+	/* isdn prepends a header in the tx path, can't share skbs */
+	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
 	dev->header_ops = NULL;
 	dev->netdev_ops = &isdn_netdev_ops;
 
```
