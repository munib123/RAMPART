# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3524_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3524_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1540-1580 of the vulnerable file.

			pr_debug("%s: change device type from %d to %d\n",
				 bond_dev->name,
				 bond_dev->type, slave_dev->type);

			res = netdev_bonding_change(bond_dev,
						    NETDEV_PRE_TYPE_CHANGE);
			res = notifier_to_errno(res);
			if (res) {
				pr_err("%s: refused to change device type\n",
				       bond_dev->name);
				res = -EBUSY;
				goto err_undo_flags;
			}

			/* Flush unicast and multicast addresses */
			dev_uc_flush(bond_dev);
			dev_mc_flush(bond_dev);

			if (slave_dev->type != ARPHRD_ETHER)
				bond_setup_by_slave(bond_dev, slave_dev);
			else
				ether_setup(bond_dev);

			netdev_bonding_change(bond_dev,
					      NETDEV_POST_TYPE_CHANGE);
		}
	} else if (bond_dev->type != slave_dev->type) {
		pr_err("%s ether type (%d) is different from other slaves (%d), can not enslave it.\n",
		       slave_dev->name,
		       slave_dev->type, bond_dev->type);
		res = -EINVAL;
		goto err_undo_flags;
	}

	if (slave_ops->ndo_set_mac_address == NULL) {
		if (bond->slave_cnt == 0) {
			pr_warning("%s: Warning: The first slave device specified does not support setting the MAC address. Setting fail_over_mac to active.",
				   bond_dev->name);
			bond->params.fail_over_mac = BOND_FOM_ACTIVE;
		} else if (bond->params.fail_over_mac != BOND_FOM_ACTIVE) {
			pr_err("%s: Error: The slave device specified does not support setting the MAC address, but fail_over_mac is not set to active.\n",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1557,8 +1557,10 @@
 
 			if (slave_dev->type != ARPHRD_ETHER)
 				bond_setup_by_slave(bond_dev, slave_dev);
-			else
+			else {
 				ether_setup(bond_dev);
+				bond_dev->priv_flags &= ~IFF_TX_SKB_SHARING;
+			}
 
 			netdev_bonding_change(bond_dev,
 					      NETDEV_POST_TYPE_CHANGE);
@@ -4330,7 +4332,7 @@
 	bond_dev->tx_queue_len = 0;
 	bond_dev->flags |= IFF_MASTER|IFF_MULTICAST;
 	bond_dev->priv_flags |= IFF_BONDING;
-	bond_dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
+	bond_dev->priv_flags &= ~(IFF_XMIT_DST_RELEASE | IFF_TX_SKB_SHARING);
 
 	/* At first, we block adding VLANs. That's the only way to
 	 * prevent problems that occur when adding VLANs over an
```
