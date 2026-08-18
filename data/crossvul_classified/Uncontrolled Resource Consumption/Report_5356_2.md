# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 5356_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5356_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 1363-1403 of the vulnerable file.

	 * immediately following this IP hdr.
	 */

	/* Note : No need to call skb_gro_postpull_rcsum() here,
	 * as we already checked checksum over ipv4 header was 0
	 */
	skb_gro_pull(skb, sizeof(*iph));
	skb_set_transport_header(skb, skb_gro_offset(skb));

	pp = ops->callbacks.gro_receive(head, skb);

out_unlock:
	rcu_read_unlock();

out:
	NAPI_GRO_CB(skb)->flush |= flush;

	return pp;
}

#define SECONDS_PER_DAY	86400

/* inet_current_timestamp - Return IP network timestamp
 *
 * Return milliseconds since midnight in network byte order.
 */
__be32 inet_current_timestamp(void)
{
	u32 secs;
	u32 msecs;
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);

	/* Get secs since midnight. */
	(void)div_u64_rem(ts.tv_sec, SECONDS_PER_DAY, &secs);
	/* Convert to msecs. */
	msecs = secs * MSEC_PER_SEC;
	/* Convert nsec to msec. */
	msecs += (u32)ts.tv_nsec / NSEC_PER_MSEC;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1380,6 +1380,19 @@
 	return pp;
 }
 
+static struct sk_buff **ipip_gro_receive(struct sk_buff **head,
+					 struct sk_buff *skb)
+{
+	if (NAPI_GRO_CB(skb)->encap_mark) {
+		NAPI_GRO_CB(skb)->flush = 1;
+		return NULL;
+	}
+
+	NAPI_GRO_CB(skb)->encap_mark = 1;
+
+	return inet_gro_receive(head, skb);
+}
+
 #define SECONDS_PER_DAY	86400
 
 /* inet_current_timestamp - Return IP network timestamp
@@ -1682,7 +1695,7 @@
 static const struct net_offload ipip_offload = {
 	.callbacks = {
 		.gso_segment	= inet_gso_segment,
-		.gro_receive	= inet_gro_receive,
+		.gro_receive	= ipip_gro_receive,
 		.gro_complete	= ipip_gro_complete,
 	},
 };
```
