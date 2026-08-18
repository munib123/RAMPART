# CrossVul Fix Pair: 7PK in c
**Pair ID:** 2305_0
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2305_0`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```c
Lines 1-36 of the vulnerable file.

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack_l4proto.h>

static unsigned int nf_ct_generic_timeout __read_mostly = 600*HZ;

static inline struct nf_generic_net *generic_pernet(struct net *net)
{
	return &net->ct.nf_ct_proto.generic;
}

static bool generic_pkt_to_tuple(const struct sk_buff *skb,
				 unsigned int dataoff,
				 struct nf_conntrack_tuple *tuple)
{
	tuple->src.u.all = 0;
	tuple->dst.u.all = 0;

	return true;
}

static bool generic_invert_tuple(struct nf_conntrack_tuple *tuple,
				 const struct nf_conntrack_tuple *orig)
{
	tuple->src.u.all = 0;
	tuple->dst.u.all = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,30 @@
 #include <net/netfilter/nf_conntrack_l4proto.h>
 
 static unsigned int nf_ct_generic_timeout __read_mostly = 600*HZ;
+
+static bool nf_generic_should_process(u8 proto)
+{
+	switch (proto) {
+#ifdef CONFIG_NF_CT_PROTO_SCTP_MODULE
+	case IPPROTO_SCTP:
+		return false;
+#endif
+#ifdef CONFIG_NF_CT_PROTO_DCCP_MODULE
+	case IPPROTO_DCCP:
+		return false;
+#endif
+#ifdef CONFIG_NF_CT_PROTO_GRE_MODULE
+	case IPPROTO_GRE:
+		return false;
+#endif
+#ifdef CONFIG_NF_CT_PROTO_UDPLITE_MODULE
+	case IPPROTO_UDPLITE:
+		return false;
+#endif
+	default:
+		return true;
+	}
+}
 
 static inline struct nf_generic_net *generic_pernet(struct net *net)
 {
@@ -67,7 +91,7 @@
 static bool generic_new(struct nf_conn *ct, const struct sk_buff *skb,
 			unsigned int dataoff, unsigned int *timeouts)
 {
-	return true;
+	return nf_generic_should_process(nf_ct_protonum(ct));
 }
 
 #if IS_ENABLED(CONFIG_NF_CT_NETLINK_TIMEOUT)
```
