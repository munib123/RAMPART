# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 4936_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4936_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1395-1435 of the vulnerable file.


	atl2_setup_pcicmd(pdev);

	netdev->netdev_ops = &atl2_netdev_ops;
	netdev->ethtool_ops = &atl2_ethtool_ops;
	netdev->watchdog_timeo = 5 * HZ;
	strncpy(netdev->name, pci_name(pdev), sizeof(netdev->name) - 1);

	netdev->mem_start = mmio_start;
	netdev->mem_end = mmio_start + mmio_len;
	adapter->bd_number = cards_found;
	adapter->pci_using_64 = false;

	/* setup the private structure */
	err = atl2_sw_init(adapter);
	if (err)
		goto err_sw_init;

	err = -EIO;

	netdev->hw_features = NETIF_F_SG | NETIF_F_HW_VLAN_CTAG_RX;
	netdev->features |= (NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX);

	/* Init PHY as early as possible due to power saving issue  */
	atl2_phy_init(&adapter->hw);

	/* reset the controller to
	 * put the device in a known good starting state */

	if (atl2_reset_hw(&adapter->hw)) {
		err = -EIO;
		goto err_reset;
	}

	/* copy the MAC address out of the EEPROM */
	atl2_read_mac_addr(&adapter->hw);
	memcpy(netdev->dev_addr, adapter->hw.mac_addr, netdev->addr_len);
	if (!is_valid_ether_addr(netdev->dev_addr)) {
		err = -EIO;
		goto err_eeprom;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1412,7 +1412,7 @@
 
 	err = -EIO;
 
-	netdev->hw_features = NETIF_F_SG | NETIF_F_HW_VLAN_CTAG_RX;
+	netdev->hw_features = NETIF_F_HW_VLAN_CTAG_RX;
 	netdev->features |= (NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX);
 
 	/* Init PHY as early as possible due to power saving issue  */
```
