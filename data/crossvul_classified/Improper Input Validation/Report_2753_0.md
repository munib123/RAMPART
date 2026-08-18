# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2753_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2753_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 113-153 of the vulnerable file.

 * @hlen: packet header length, if @data is NULL use skb_headlen(skb)
 *
 * The function will try to retrieve individual keys into target specified
 * by flow_dissector from either the skbuff or a raw buffer specified by the
 * rest parameters.
 *
 * Caller must take care of zeroing target container memory.
 */
bool __skb_flow_dissect(const struct sk_buff *skb,
			struct flow_dissector *flow_dissector,
			void *target_container,
			void *data, __be16 proto, int nhoff, int hlen)
{
	struct flow_dissector_key_control *key_control;
	struct flow_dissector_key_basic *key_basic;
	struct flow_dissector_key_addrs *key_addrs;
	struct flow_dissector_key_ports *key_ports;
	struct flow_dissector_key_tags *key_tags;
	struct flow_dissector_key_keyid *key_keyid;
	u8 ip_proto = 0;

	if (!data) {
		data = skb->data;
		proto = skb->protocol;
		nhoff = skb_network_offset(skb);
		hlen = skb_headlen(skb);
	}

	/* It is ensured by skb_flow_dissector_init() that control key will
	 * be always present.
	 */
	key_control = skb_flow_dissector_target(flow_dissector,
						FLOW_DISSECTOR_KEY_CONTROL,
						target_container);

	/* It is ensured by skb_flow_dissector_init() that basic key will
	 * be always present.
	 */
	key_basic = skb_flow_dissector_target(flow_dissector,
					      FLOW_DISSECTOR_KEY_BASIC,
					      target_container);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -130,6 +130,7 @@
 	struct flow_dissector_key_tags *key_tags;
 	struct flow_dissector_key_keyid *key_keyid;
 	u8 ip_proto = 0;
+	bool ret = false;
 
 	if (!data) {
 		data = skb->data;
@@ -171,7 +172,7 @@
 ip:
 		iph = __skb_header_pointer(skb, nhoff, sizeof(_iph), data, hlen, &_iph);
 		if (!iph || iph->ihl < 5)
-			return false;
+			goto out_bad;
 		nhoff += iph->ihl * 4;
 
 		ip_proto = iph->protocol;
@@ -197,7 +198,7 @@
 ipv6:
 		iph = __skb_header_pointer(skb, nhoff, sizeof(_iph), data, hlen, &_iph);
 		if (!iph)
-			return false;
+			goto out_bad;
 
 		ip_proto = iph->nexthdr;
 		nhoff += sizeof(struct ipv6hdr);
@@ -234,7 +235,7 @@
 
 		vlan = __skb_header_pointer(skb, nhoff, sizeof(_vlan), data, hlen, &_vlan);
 		if (!vlan)
-			return false;
+			goto out_bad;
 
 		if (skb_flow_dissector_uses_key(flow_dissector,
 						FLOW_DISSECTOR_KEY_VLANID)) {
@@ -256,7 +257,7 @@
 		} *hdr, _hdr;
 		hdr = __skb_header_pointer(skb, nhoff, sizeof(_hdr), data, hlen, &_hdr);
 		if (!hdr)
-			return false;
+			goto out_bad;
 		proto = hdr->proto;
 		nhoff += PPPOE_SES_HLEN;
 		switch (proto) {
@@ -265,7 +266,7 @@
 		case htons(PPP_IPV6):
 			goto ipv6;
 		default:
-			return false;
+			goto out_bad;
 		}
 	}
 	case htons(ETH_P_TIPC): {
@@ -275,9 +276,7 @@
 		} *hdr, _hdr;
 		hdr = __skb_header_pointer(skb, nhoff, sizeof(_hdr), data, hlen, &_hdr);
 		if (!hdr)
-			return false;
-		key_basic->n_proto = proto;
-		key_control->thoff = (u16)nhoff;
+			goto out_bad;
 
 		if (skb_flow_dissector_uses_key(flow_dissector,
 						FLOW_DISSECTOR_KEY_TIPC_ADDRS)) {
@@ -287,7 +286,7 @@
 			key_addrs->tipcaddrs.srcnode = hdr->srcnode;
 			key_control->addr_type = FLOW_DISSECTOR_KEY_TIPC_ADDRS;
 		}
-		return true;
+		goto out_good;
 	}
 
 	case htons(ETH_P_MPLS_UC):
@@ -297,7 +296,7 @@
 		hdr = __skb_header_pointer(skb, nhoff, sizeof(_hdr), data,
 					   hlen, &_hdr);
 		if (!hdr)
-			return false;
+			goto out_bad;
 
 		if ((ntohl(hdr[0].entry) & MPLS_LS_LABEL_MASK) >>
 		     MPLS_LS_LABEL_SHIFT == MPLS_LABEL_ENTROPY) {
@@ -310,21 +309,17 @@
 					htonl(MPLS_LS_LABEL_MASK);
 			}
 
-			key_basic->n_proto = proto;
-			key_basic->ip_proto = ip_proto;
-			key_control->thoff = (u16)nhoff;
-
-			return true;
-		}
-
-		return true;
+			goto out_good;
+		}
+
+		goto out_good;
 	}
 
 	case htons(ETH_P_FCOE):
 		key_control->thoff = (u16)(nhoff + FCOE_HEADER_LEN);
 		/* fall through */
 	default:
-		return false;
+		goto out_bad;
 	}
 
 ip_proto_again:
@@ -337,7 +332,7 @@
 
 		hdr = __skb_header_pointer(skb, nhoff, sizeof(_hdr), data, hlen, &_hdr);
 		if (!hdr)
-			return false;
+			goto out_bad;
 		/*
 		 * Only look inside GRE if version zero and no
 		 * routing
@@ -357,7 +352,7 @@
 						     data, hlen, &_keyid);
 
 			if (!keyid)
-				return false;
+				goto out_bad;
 
 			if (skb_flow_dissector_uses_key(flow_dissector,
 							FLOW_DISSECTOR_KEY_GRE_KEYID)) {
@@ -378,7 +373,7 @@
 						   sizeof(_eth),
 						   data, hlen, &_eth);
 			if (!eth)
-				return false;
+				goto out_bad;
 			proto = eth->h_proto;
 			nhoff += sizeof(*eth);
 		}
@@ -395,7 +390,7 @@
 		opthdr = __skb_header_pointer(skb, nhoff, sizeof(_opthdr),
 					      data, hlen, &_opthdr);
 		if (!opthdr)
-			return false;
+			goto out_bad;
 
 		ip_proto = opthdr[0];
 		nhoff += (opthdr[1] + 1) << 3;
@@ -415,10 +410,6 @@
 		break;
 	}
 
-	key_basic->n_proto = proto;
-	key_basic->ip_proto = ip_proto;
-	key_control->thoff = (u16)nhoff;
-
 	if (skb_flow_dissector_uses_key(flow_dissector,
 					FLOW_DISSECTOR_KEY_PORTS)) {
 		key_ports = skb_flow_dissector_target(flow_dissector,
@@ -428,7 +419,15 @@
 							data, hlen);
 	}
 
-	return true;
+out_good:
+	ret = true;
+
+out_bad:
+	key_basic->n_proto = proto;
+	key_basic->ip_proto = ip_proto;
+	key_control->thoff = (u16)nhoff;
+
+	return ret;
 }
 EXPORT_SYMBOL(__skb_flow_dissect);
 
```
