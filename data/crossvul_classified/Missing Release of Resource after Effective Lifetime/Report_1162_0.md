# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 1162_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1162_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 469-509 of the vulnerable file.

	ether_addr_copy(hsr->sup_multicast_addr, def_multicast_addr);
	hsr->sup_multicast_addr[ETH_ALEN - 1] = multicast_spec;

	hsr->protVersion = protocol_version;

	/* FIXME: should I modify the value of these?
	 *
	 * - hsr_dev->flags - i.e.
	 *			IFF_MASTER/SLAVE?
	 * - hsr_dev->priv_flags - i.e.
	 *			IFF_EBRIDGE?
	 *			IFF_TX_SKB_SHARING?
	 *			IFF_HSR_MASTER/SLAVE?
	 */

	/* Make sure the 1st call to netif_carrier_on() gets through */
	netif_carrier_off(hsr_dev);

	res = hsr_add_port(hsr, hsr_dev, HSR_PT_MASTER);
	if (res)
		return res;

	res = register_netdevice(hsr_dev);
	if (res)
		goto fail;

	res = hsr_add_port(hsr, slave[0], HSR_PT_SLAVE_A);
	if (res)
		goto fail;
	res = hsr_add_port(hsr, slave[1], HSR_PT_SLAVE_B);
	if (res)
		goto fail;

	mod_timer(&hsr->prune_timer, jiffies + msecs_to_jiffies(PRUNE_PERIOD));

	return 0;

fail:
	hsr_for_each_port(hsr, port)
		hsr_del_port(port);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -486,7 +486,7 @@
 
 	res = hsr_add_port(hsr, hsr_dev, HSR_PT_MASTER);
 	if (res)
-		return res;
+		goto err_add_port;
 
 	res = register_netdevice(hsr_dev);
 	if (res)
@@ -506,6 +506,8 @@
 fail:
 	hsr_for_each_port(hsr, port)
 		hsr_del_port(port);
+err_add_port:
+	hsr_del_node(&hsr->self_node_db);
 
 	return res;
 }
```
