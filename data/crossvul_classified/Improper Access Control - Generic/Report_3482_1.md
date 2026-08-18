# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3482_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3482_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 787-827 of the vulnerable file.

		h.h2->tp_mac = macoff;
		h.h2->tp_net = netoff;
		if ((po->tp_tstamp & SOF_TIMESTAMPING_SYS_HARDWARE)
				&& shhwtstamps->syststamp.tv64)
			ts = ktime_to_timespec(shhwtstamps->syststamp);
		else if ((po->tp_tstamp & SOF_TIMESTAMPING_RAW_HARDWARE)
				&& shhwtstamps->hwtstamp.tv64)
			ts = ktime_to_timespec(shhwtstamps->hwtstamp);
		else if (skb->tstamp.tv64)
			ts = ktime_to_timespec(skb->tstamp);
		else
			getnstimeofday(&ts);
		h.h2->tp_sec = ts.tv_sec;
		h.h2->tp_nsec = ts.tv_nsec;
		if (vlan_tx_tag_present(skb)) {
			h.h2->tp_vlan_tci = vlan_tx_tag_get(skb);
			status |= TP_STATUS_VLAN_VALID;
		} else {
			h.h2->tp_vlan_tci = 0;
		}
		hdrlen = sizeof(*h.h2);
		break;
	default:
		BUG();
	}

	sll = h.raw + TPACKET_ALIGN(hdrlen);
	sll->sll_halen = dev_parse_header(skb, sll->sll_addr);
	sll->sll_family = AF_PACKET;
	sll->sll_hatype = dev->type;
	sll->sll_protocol = skb->protocol;
	sll->sll_pkttype = skb->pkt_type;
	if (unlikely(po->origdev))
		sll->sll_ifindex = orig_dev->ifindex;
	else
		sll->sll_ifindex = dev->ifindex;

	__packet_set_status(po, h.raw, status);
	smp_mb();
#if ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE == 1
	{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -804,6 +804,7 @@
 		} else {
 			h.h2->tp_vlan_tci = 0;
 		}
+		h.h2->tp_padding = 0;
 		hdrlen = sizeof(*h.h2);
 		break;
 	default:
@@ -1736,6 +1737,7 @@
 		} else {
 			aux.tp_vlan_tci = 0;
 		}
+		aux.tp_padding = 0;
 		put_cmsg(msg, SOL_PACKET, PACKET_AUXDATA, sizeof(aux), &aux);
 	}
 
```
