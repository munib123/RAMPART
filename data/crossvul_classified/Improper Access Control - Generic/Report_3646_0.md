# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3646_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3646_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1242-1285 of the vulnerable file.

}

static u32 rio_get_link(struct net_device *dev)
{
	struct netdev_private *np = netdev_priv(dev);
	return np->link_status;
}

static const struct ethtool_ops ethtool_ops = {
	.get_drvinfo = rio_get_drvinfo,
	.get_settings = rio_get_settings,
	.set_settings = rio_set_settings,
	.get_link = rio_get_link,
};

static int
rio_ioctl (struct net_device *dev, struct ifreq *rq, int cmd)
{
	int phy_addr;
	struct netdev_private *np = netdev_priv(dev);
	struct mii_data *miidata = (struct mii_data *) &rq->ifr_ifru;

	struct netdev_desc *desc;
	int i;

	phy_addr = np->phy_addr;
	switch (cmd) {
	case SIOCDEVPRIVATE:
		break;

	case SIOCDEVPRIVATE + 1:
		miidata->out_value = mii_read (dev, phy_addr, miidata->reg_num);
		break;
	case SIOCDEVPRIVATE + 2:
		mii_write (dev, phy_addr, miidata->reg_num, miidata->in_value);
		break;
	case SIOCDEVPRIVATE + 3:
		break;
	case SIOCDEVPRIVATE + 4:
		break;
	case SIOCDEVPRIVATE + 5:
		netif_stop_queue (dev);
		break;
	case SIOCDEVPRIVATE + 6:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1259,55 +1259,21 @@
 {
 	int phy_addr;
 	struct netdev_private *np = netdev_priv(dev);
-	struct mii_data *miidata = (struct mii_data *) &rq->ifr_ifru;
-
-	struct netdev_desc *desc;
-	int i;
+	struct mii_ioctl_data *miidata = if_mii(rq);
 
 	phy_addr = np->phy_addr;
 	switch (cmd) {
-	case SIOCDEVPRIVATE:
+	case SIOCGMIIPHY:
+		miidata->phy_id = phy_addr;
 		break;
-
-	case SIOCDEVPRIVATE + 1:
-		miidata->out_value = mii_read (dev, phy_addr, miidata->reg_num);
+	case SIOCGMIIREG:
+		miidata->val_out = mii_read (dev, phy_addr, miidata->reg_num);
 		break;
-	case SIOCDEVPRIVATE + 2:
-		mii_write (dev, phy_addr, miidata->reg_num, miidata->in_value);
+	case SIOCSMIIREG:
+		if (!capable(CAP_NET_ADMIN))
+			return -EPERM;
+		mii_write (dev, phy_addr, miidata->reg_num, miidata->val_in);
 		break;
-	case SIOCDEVPRIVATE + 3:
-		break;
-	case SIOCDEVPRIVATE + 4:
-		break;
-	case SIOCDEVPRIVATE + 5:
-		netif_stop_queue (dev);
-		break;
-	case SIOCDEVPRIVATE + 6:
-		netif_wake_queue (dev);
-		break;
-	case SIOCDEVPRIVATE + 7:
-		printk
-		    ("tx_full=%x cur_tx=%lx old_tx=%lx cur_rx=%lx old_rx=%lx\n",
-		     netif_queue_stopped(dev), np->cur_tx, np->old_tx, np->cur_rx,
-		     np->old_rx);
-		break;
-	case SIOCDEVPRIVATE + 8:
-		printk("TX ring:\n");
-		for (i = 0; i < TX_RING_SIZE; i++) {
-			desc = &np->tx_ring[i];
-			printk
-			    ("%02x:cur:%08x next:%08x status:%08x frag1:%08x frag0:%08x",
-			     i,
-			     (u32) (np->tx_ring_dma + i * sizeof (*desc)),
-			     (u32)le64_to_cpu(desc->next_desc),
-			     (u32)le64_to_cpu(desc->status),
-			     (u32)(le64_to_cpu(desc->fraginfo) >> 32),
-			     (u32)le64_to_cpu(desc->fraginfo));
-			printk ("\n");
-		}
-		printk ("\n");
-		break;
-
 	default:
 		return -EOPNOTSUPP;
 	}
```
