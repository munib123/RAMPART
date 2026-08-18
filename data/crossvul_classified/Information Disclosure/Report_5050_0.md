# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5050_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5050_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1163-1210 of the vulnerable file.

	if (nla_put_u64(skb, IFLA_VF_STATS_RX_PACKETS,
			vf_stats.rx_packets) ||
	    nla_put_u64(skb, IFLA_VF_STATS_TX_PACKETS,
			vf_stats.tx_packets) ||
	    nla_put_u64(skb, IFLA_VF_STATS_RX_BYTES,
			vf_stats.rx_bytes) ||
	    nla_put_u64(skb, IFLA_VF_STATS_TX_BYTES,
			vf_stats.tx_bytes) ||
	    nla_put_u64(skb, IFLA_VF_STATS_BROADCAST,
			vf_stats.broadcast) ||
	    nla_put_u64(skb, IFLA_VF_STATS_MULTICAST,
			vf_stats.multicast))
		return -EMSGSIZE;
	nla_nest_end(skb, vfstats);
	nla_nest_end(skb, vf);
	return 0;
}

static int rtnl_fill_link_ifmap(struct sk_buff *skb, struct net_device *dev)
{
	struct rtnl_link_ifmap map = {
		.mem_start   = dev->mem_start,
		.mem_end     = dev->mem_end,
		.base_addr   = dev->base_addr,
		.irq         = dev->irq,
		.dma         = dev->dma,
		.port        = dev->if_port,
	};
	if (nla_put(skb, IFLA_MAP, sizeof(map), &map))
		return -EMSGSIZE;

	return 0;
}

static int rtnl_fill_ifinfo(struct sk_buff *skb, struct net_device *dev,
			    int type, u32 pid, u32 seq, u32 change,
			    unsigned int flags, u32 ext_filter_mask)
{
	struct ifinfomsg *ifm;
	struct nlmsghdr *nlh;
	struct nlattr *af_spec;
	struct rtnl_af_ops *af_ops;
	struct net_device *upper_dev = netdev_master_upper_dev_get(dev);

	ASSERT_RTNL();
	nlh = nlmsg_put(skb, pid, seq, type, sizeof(*ifm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1180,14 +1180,16 @@
 
 static int rtnl_fill_link_ifmap(struct sk_buff *skb, struct net_device *dev)
 {
-	struct rtnl_link_ifmap map = {
-		.mem_start   = dev->mem_start,
-		.mem_end     = dev->mem_end,
-		.base_addr   = dev->base_addr,
-		.irq         = dev->irq,
-		.dma         = dev->dma,
-		.port        = dev->if_port,
-	};
+	struct rtnl_link_ifmap map;
+
+	memset(&map, 0, sizeof(map));
+	map.mem_start   = dev->mem_start;
+	map.mem_end     = dev->mem_end;
+	map.base_addr   = dev->base_addr;
+	map.irq         = dev->irq;
+	map.dma         = dev->dma;
+	map.port        = dev->if_port;
+
 	if (nla_put(skb, IFLA_MAP, sizeof(map), &map))
 		return -EMSGSIZE;
 
```
