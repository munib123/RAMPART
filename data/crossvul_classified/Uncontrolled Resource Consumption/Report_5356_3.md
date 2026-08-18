# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 5356_3
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5356_3`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 108-148 of the vulnerable file.

		pcsum = (__be32 *)(greh + 1);

		*pcsum = 0;
		*(__sum16 *)pcsum = gso_make_checksum(skb, 0);
	} while ((skb = skb->next));
out:
	return segs;
}

static struct sk_buff **gre_gro_receive(struct sk_buff **head,
					struct sk_buff *skb)
{
	struct sk_buff **pp = NULL;
	struct sk_buff *p;
	const struct gre_base_hdr *greh;
	unsigned int hlen, grehlen;
	unsigned int off;
	int flush = 1;
	struct packet_offload *ptype;
	__be16 type;

	off = skb_gro_offset(skb);
	hlen = off + sizeof(*greh);
	greh = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, hlen)) {
		greh = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!greh))
			goto out;
	}

	/* Only support version 0 and K (key), C (csum) flags. Note that
	 * although the support for the S (seq#) flag can be added easily
	 * for GRO, this is problematic for GSO hence can not be enabled
	 * here because a GRO pkt may end up in the forwarding path, thus
	 * requiring GSO support to break it up correctly.
	 */
	if ((greh->flags & ~(GRE_KEY|GRE_CSUM)) != 0)
		goto out;

	type = greh->protocol;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -125,6 +125,11 @@
 	int flush = 1;
 	struct packet_offload *ptype;
 	__be16 type;
+
+	if (NAPI_GRO_CB(skb)->encap_mark)
+		goto out;
+
+	NAPI_GRO_CB(skb)->encap_mark = 1;
 
 	off = skb_gro_offset(skb);
 	hlen = off + sizeof(*greh);
```
