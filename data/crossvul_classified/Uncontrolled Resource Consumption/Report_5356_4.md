# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 5356_4
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5356_4`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 294-334 of the vulnerable file.

		}
		head = &uo_priv->next;
	}
	pr_warn("udp_del_offload: didn't find offload for port %d\n", ntohs(uo->port));
unlock:
	spin_unlock(&udp_offload_lock);
	if (uo_priv)
		call_rcu(&uo_priv->rcu, udp_offload_free_routine);
}
EXPORT_SYMBOL(udp_del_offload);

struct sk_buff **udp_gro_receive(struct sk_buff **head, struct sk_buff *skb,
				 struct udphdr *uh)
{
	struct udp_offload_priv *uo_priv;
	struct sk_buff *p, **pp = NULL;
	struct udphdr *uh2;
	unsigned int off = skb_gro_offset(skb);
	int flush = 1;

	if (NAPI_GRO_CB(skb)->udp_mark ||
	    (skb->ip_summed != CHECKSUM_PARTIAL &&
	     NAPI_GRO_CB(skb)->csum_cnt == 0 &&
	     !NAPI_GRO_CB(skb)->csum_valid))
		goto out;

	/* mark that this skb passed once through the udp gro layer */
	NAPI_GRO_CB(skb)->udp_mark = 1;

	rcu_read_lock();
	uo_priv = rcu_dereference(udp_offload_base);
	for (; uo_priv != NULL; uo_priv = rcu_dereference(uo_priv->next)) {
		if (net_eq(read_pnet(&uo_priv->net), dev_net(skb->dev)) &&
		    uo_priv->offload->port == uh->dest &&
		    uo_priv->offload->callbacks.gro_receive)
			goto unflush;
	}
	goto out_unlock;

unflush:
	flush = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -311,14 +311,14 @@
 	unsigned int off = skb_gro_offset(skb);
 	int flush = 1;
 
-	if (NAPI_GRO_CB(skb)->udp_mark ||
+	if (NAPI_GRO_CB(skb)->encap_mark ||
 	    (skb->ip_summed != CHECKSUM_PARTIAL &&
 	     NAPI_GRO_CB(skb)->csum_cnt == 0 &&
 	     !NAPI_GRO_CB(skb)->csum_valid))
 		goto out;
 
-	/* mark that this skb passed once through the udp gro layer */
-	NAPI_GRO_CB(skb)->udp_mark = 1;
+	/* mark that this skb passed once through the tunnel gro layer */
+	NAPI_GRO_CB(skb)->encap_mark = 1;
 
 	rcu_read_lock();
 	uo_priv = rcu_dereference(udp_offload_base);
```
