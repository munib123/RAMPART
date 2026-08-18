# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3018_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3018_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 75-99 of the vulnerable file.

	int link;
	u64 tx_timeout_count;

	unsigned long state;

	struct timer_list service_timer;

	struct work_struct service_task;

	struct notifier_block notifier_block;
};

#define tx_ring_data(priv, idx) ((priv)->ring_data[idx])
#define rx_ring_data(priv, idx) \
	((priv)->ring_data[(priv)->ae_handle->q_num + (idx)])

void hns_ethtool_set_ops(struct net_device *ndev);
void hns_nic_net_reset(struct net_device *ndev);
void hns_nic_net_reinit(struct net_device *netdev);
int hns_nic_init_phy(struct net_device *ndev, struct hnae_handle *h);
int hns_nic_net_xmit_hw(struct net_device *ndev,
			struct sk_buff *skb,
			struct hns_nic_ring_data *ring_data);

#endif	/**__HNS_ENET_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -92,8 +92,8 @@
 void hns_nic_net_reset(struct net_device *ndev);
 void hns_nic_net_reinit(struct net_device *netdev);
 int hns_nic_init_phy(struct net_device *ndev, struct hnae_handle *h);
-int hns_nic_net_xmit_hw(struct net_device *ndev,
-			struct sk_buff *skb,
-			struct hns_nic_ring_data *ring_data);
+netdev_tx_t hns_nic_net_xmit_hw(struct net_device *ndev,
+				struct sk_buff *skb,
+				struct hns_nic_ring_data *ring_data);
 
 #endif	/**__HNS_ENET_H */
```
