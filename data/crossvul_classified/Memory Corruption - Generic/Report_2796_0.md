# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2796_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2796_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2174-2214 of the vulnerable file.

		kfree_skb(skb);
	return 0;
}

static int tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
		       struct packet_type *pt, struct net_device *orig_dev)
{
	struct sock *sk;
	struct packet_sock *po;
	struct sockaddr_ll *sll;
	union tpacket_uhdr h;
	u8 *skb_head = skb->data;
	int skb_len = skb->len;
	unsigned int snaplen, res;
	unsigned long status = TP_STATUS_USER;
	unsigned short macoff, netoff, hdrlen;
	struct sk_buff *copy_skb = NULL;
	struct timespec ts;
	__u32 ts_status;
	bool is_drop_n_account = false;

	/* struct tpacket{2,3}_hdr is aligned to a multiple of TPACKET_ALIGNMENT.
	 * We may add members to them until current aligned size without forcing
	 * userspace to call getsockopt(..., PACKET_HDRLEN, ...).
	 */
	BUILD_BUG_ON(TPACKET_ALIGN(sizeof(*h.h2)) != 32);
	BUILD_BUG_ON(TPACKET_ALIGN(sizeof(*h.h3)) != 48);

	if (skb->pkt_type == PACKET_LOOPBACK)
		goto drop;

	sk = pt->af_packet_priv;
	po = pkt_sk(sk);

	if (!net_eq(dev_net(dev), sock_net(sk)))
		goto drop;

	if (dev->header_ops) {
		if (sk->sk_type != SOCK_DGRAM)
			skb_push(skb, skb->data - skb_mac_header(skb));
		else if (skb->pkt_type == PACKET_OUTGOING) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2191,6 +2191,7 @@
 	struct timespec ts;
 	__u32 ts_status;
 	bool is_drop_n_account = false;
+	bool do_vnet = false;
 
 	/* struct tpacket{2,3}_hdr is aligned to a multiple of TPACKET_ALIGNMENT.
 	 * We may add members to them until current aligned size without forcing
@@ -2241,8 +2242,10 @@
 		netoff = TPACKET_ALIGN(po->tp_hdrlen +
 				       (maclen < 16 ? 16 : maclen)) +
 				       po->tp_reserve;
-		if (po->has_vnet_hdr)
+		if (po->has_vnet_hdr) {
 			netoff += sizeof(struct virtio_net_hdr);
+			do_vnet = true;
+		}
 		macoff = netoff - maclen;
 	}
 	if (po->tp_version <= TPACKET_V2) {
@@ -2259,8 +2262,10 @@
 					skb_set_owner_r(copy_skb, sk);
 			}
 			snaplen = po->rx_ring.frame_size - macoff;
-			if ((int)snaplen < 0)
+			if ((int)snaplen < 0) {
 				snaplen = 0;
+				do_vnet = false;
+			}
 		}
 	} else if (unlikely(macoff + snaplen >
 			    GET_PBDQC_FROM_RB(&po->rx_ring)->max_frame_len)) {
@@ -2273,6 +2278,7 @@
 		if (unlikely((int)snaplen < 0)) {
 			snaplen = 0;
 			macoff = GET_PBDQC_FROM_RB(&po->rx_ring)->max_frame_len;
+			do_vnet = false;
 		}
 	}
 	spin_lock(&sk->sk_receive_queue.lock);
@@ -2298,7 +2304,7 @@
 	}
 	spin_unlock(&sk->sk_receive_queue.lock);
 
-	if (po->has_vnet_hdr) {
+	if (do_vnet) {
 		if (virtio_net_hdr_from_skb(skb, h.raw + macoff -
 					    sizeof(struct virtio_net_hdr),
 					    vio_le(), true)) {
```
