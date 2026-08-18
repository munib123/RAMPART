# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 5346_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5346_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 561-601 of the vulnerable file.

	return -ENOENT;
}

static int fwnet_incoming_packet(struct fwnet_device *dev, __be32 *buf, int len,
				 int source_node_id, int generation,
				 bool is_broadcast)
{
	struct sk_buff *skb;
	struct net_device *net = dev->netdev;
	struct rfc2734_header hdr;
	unsigned lf;
	unsigned long flags;
	struct fwnet_peer *peer;
	struct fwnet_partial_datagram *pd;
	int fg_off;
	int dg_size;
	u16 datagram_label;
	int retval;
	u16 ether_type;

	hdr.w0 = be32_to_cpu(buf[0]);
	lf = fwnet_get_hdr_lf(&hdr);
	if (lf == RFC2374_HDR_UNFRAG) {
		/*
		 * An unfragmented datagram has been received by the ieee1394
		 * bus. Build an skbuff around it so we can pass it to the
		 * high level network layer.
		 */
		ether_type = fwnet_get_hdr_ether_type(&hdr);
		buf++;
		len -= RFC2374_UNFRAG_HDR_SIZE;

		skb = dev_alloc_skb(len + LL_RESERVED_SPACE(net));
		if (unlikely(!skb)) {
			net->stats.rx_dropped++;

			return -ENOMEM;
		}
		skb_reserve(skb, LL_RESERVED_SPACE(net));
		memcpy(skb_put(skb, len), buf, len);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -578,6 +578,9 @@
 	int retval;
 	u16 ether_type;
 
+	if (len <= RFC2374_UNFRAG_HDR_SIZE)
+		return 0;
+
 	hdr.w0 = be32_to_cpu(buf[0]);
 	lf = fwnet_get_hdr_lf(&hdr);
 	if (lf == RFC2374_HDR_UNFRAG) {
@@ -602,7 +605,12 @@
 		return fwnet_finish_incoming_packet(net, skb, source_node_id,
 						    is_broadcast, ether_type);
 	}
+
 	/* A datagram fragment has been received, now the fun begins. */
+
+	if (len <= RFC2374_FRAG_HDR_SIZE)
+		return 0;
+
 	hdr.w1 = ntohl(buf[1]);
 	buf += 2;
 	len -= RFC2374_FRAG_HDR_SIZE;
@@ -615,6 +623,9 @@
 	}
 	datagram_label = fwnet_get_hdr_dgl(&hdr);
 	dg_size = fwnet_get_hdr_dg_size(&hdr); /* ??? + 1 */
+
+	if (fg_off + len > dg_size)
+		return 0;
 
 	spin_lock_irqsave(&dev->lock, flags);
 
@@ -722,6 +733,22 @@
 	fw_send_response(card, r, rcode);
 }
 
+static int gasp_source_id(__be32 *p)
+{
+	return be32_to_cpu(p[0]) >> 16;
+}
+
+static u32 gasp_specifier_id(__be32 *p)
+{
+	return (be32_to_cpu(p[0]) & 0xffff) << 8 |
+	       (be32_to_cpu(p[1]) & 0xff000000) >> 24;
+}
+
+static u32 gasp_version(__be32 *p)
+{
+	return be32_to_cpu(p[1]) & 0xffffff;
+}
+
 static void fwnet_receive_broadcast(struct fw_iso_context *context,
 		u32 cycle, size_t header_length, void *header, void *data)
 {
@@ -731,9 +758,6 @@
 	__be32 *buf_ptr;
 	int retval;
 	u32 length;
-	u16 source_node_id;
-	u32 specifier_id;
-	u32 ver;
 	unsigned long offset;
 	unsigned long flags;
 
@@ -750,22 +774,17 @@
 
 	spin_unlock_irqrestore(&dev->lock, flags);
 
-	specifier_id =    (be32_to_cpu(buf_ptr[0]) & 0xffff) << 8
-			| (be32_to_cpu(buf_ptr[1]) & 0xff000000) >> 24;
-	ver = be32_to_cpu(buf_ptr[1]) & 0xffffff;
-	source_node_id = be32_to_cpu(buf_ptr[0]) >> 16;
-
-	if (specifier_id == IANA_SPECIFIER_ID &&
-	    (ver == RFC2734_SW_VERSION
+	if (length > IEEE1394_GASP_HDR_SIZE &&
+	    gasp_specifier_id(buf_ptr) == IANA_SPECIFIER_ID &&
+	    (gasp_version(buf_ptr) == RFC2734_SW_VERSION
 #if IS_ENABLED(CONFIG_IPV6)
-	     || ver == RFC3146_SW_VERSION
+	     || gasp_version(buf_ptr) == RFC3146_SW_VERSION
 #endif
-	    )) {
-		buf_ptr += 2;
-		length -= IEEE1394_GASP_HDR_SIZE;
-		fwnet_incoming_packet(dev, buf_ptr, length, source_node_id,
+	    ))
+		fwnet_incoming_packet(dev, buf_ptr + 2,
+				      length - IEEE1394_GASP_HDR_SIZE,
+				      gasp_source_id(buf_ptr),
 				      context->card->generation, true);
-	}
 
 	packet.payload_length = dev->rcv_buffer_size;
 	packet.interrupt = 1;
```
