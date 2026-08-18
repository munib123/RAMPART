# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 5356_5
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5356_5`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 241-281 of the vulnerable file.


		/* Clear flush_id, there's really no concept of ID in IPv6. */
		NAPI_GRO_CB(p)->flush_id = 0;
	}

	NAPI_GRO_CB(skb)->flush |= flush;

	skb_gro_postpull_rcsum(skb, iph, nlen);

	pp = ops->callbacks.gro_receive(head, skb);

out_unlock:
	rcu_read_unlock();

out:
	NAPI_GRO_CB(skb)->flush |= flush;

	return pp;
}

static int ipv6_gro_complete(struct sk_buff *skb, int nhoff)
{
	const struct net_offload *ops;
	struct ipv6hdr *iph = (struct ipv6hdr *)(skb->data + nhoff);
	int err = -ENOSYS;

	if (skb->encapsulation)
		skb_set_inner_network_header(skb, nhoff);

	iph->payload_len = htons(skb->len - nhoff - sizeof(*iph));

	rcu_read_lock();

	nhoff += sizeof(*iph) + ipv6_exthdrs_len(iph, &ops);
	if (WARN_ON(!ops || !ops->callbacks.gro_complete))
		goto out_unlock;

	err = ops->callbacks.gro_complete(skb, nhoff);

out_unlock:
	rcu_read_unlock();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -258,6 +258,19 @@
 	return pp;
 }
 
+static struct sk_buff **sit_gro_receive(struct sk_buff **head,
+					struct sk_buff *skb)
+{
+	if (NAPI_GRO_CB(skb)->encap_mark) {
+		NAPI_GRO_CB(skb)->flush = 1;
+		return NULL;
+	}
+
+	NAPI_GRO_CB(skb)->encap_mark = 1;
+
+	return ipv6_gro_receive(head, skb);
+}
+
 static int ipv6_gro_complete(struct sk_buff *skb, int nhoff)
 {
 	const struct net_offload *ops;
@@ -302,7 +315,7 @@
 static const struct net_offload sit_offload = {
 	.callbacks = {
 		.gso_segment	= ipv6_gso_segment,
-		.gro_receive    = ipv6_gro_receive,
+		.gro_receive    = sit_gro_receive,
 		.gro_complete   = sit_gro_complete,
 	},
 };
```
