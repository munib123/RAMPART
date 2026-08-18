# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3524_8
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3524_8`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 838-878 of the vulnerable file.

static const struct net_device_ops hostap_master_ops = {
	.ndo_start_xmit 	= hostap_master_start_xmit,

	.ndo_open		= prism2_open,
	.ndo_stop		= prism2_close,
	.ndo_do_ioctl		= hostap_ioctl,
	.ndo_set_mac_address	= prism2_set_mac_address,
	.ndo_set_multicast_list = hostap_set_multicast_list,
	.ndo_change_mtu 	= prism2_change_mtu,
	.ndo_tx_timeout 	= prism2_tx_timeout,
	.ndo_validate_addr	= eth_validate_addr,
};

void hostap_setup_dev(struct net_device *dev, local_info_t *local,
		      int type)
{
	struct hostap_interface *iface;

	iface = netdev_priv(dev);
	ether_setup(dev);

	/* kernel callbacks */
	if (iface) {
		/* Currently, we point to the proper spy_data only on
		 * the main_dev. This could be fixed. Jean II */
		iface->wireless_data.spy_data = &iface->spy_data;
		dev->wireless_data = &iface->wireless_data;
	}
	dev->wireless_handlers = &hostap_iw_handler_def;
	dev->watchdog_timeo = TX_TIMEOUT;

	switch(type) {
	case HOSTAP_INTERFACE_AP:
		dev->tx_queue_len = 0;	/* use main radio device queue */
		dev->netdev_ops = &hostap_mgmt_netdev_ops;
		dev->type = ARPHRD_IEEE80211;
		dev->header_ops = &hostap_80211_ops;
		break;
	case HOSTAP_INTERFACE_MASTER:
		dev->netdev_ops = &hostap_master_ops;
		break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -855,6 +855,7 @@
 
 	iface = netdev_priv(dev);
 	ether_setup(dev);
+	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
 
 	/* kernel callbacks */
 	if (iface) {
```
