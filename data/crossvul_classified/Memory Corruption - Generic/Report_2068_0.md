# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2068_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2068_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 17-57 of the vulnerable file.


#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <linux/netfilter/nf_conntrack_irc.h>

MODULE_AUTHOR("Harald Welte <laforge@gnumonks.org>");
MODULE_DESCRIPTION("IRC (DCC) NAT helper");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ip_nat_irc");

static unsigned int help(struct sk_buff *skb,
			 enum ip_conntrack_info ctinfo,
			 unsigned int protoff,
			 unsigned int matchoff,
			 unsigned int matchlen,
			 struct nf_conntrack_expect *exp)
{
	char buffer[sizeof("4294967296 65635")];
	u_int16_t port;
	unsigned int ret;

	/* Reply comes from server. */
	exp->saved_proto.tcp.port = exp->tuple.dst.u.tcp.port;
	exp->dir = IP_CT_DIR_REPLY;
	exp->expectfn = nf_nat_follow_master;

	/* Try to get same port: if not, try to change it. */
	for (port = ntohs(exp->saved_proto.tcp.port); port != 0; port++) {
		int ret;

		exp->tuple.dst.u.tcp.port = htons(port);
		ret = nf_ct_expect_related(exp);
		if (ret == 0)
			break;
		else if (ret != -EBUSY) {
			port = 0;
			break;
		}
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,10 +34,14 @@
 			 struct nf_conntrack_expect *exp)
 {
 	char buffer[sizeof("4294967296 65635")];
+	struct nf_conn *ct = exp->master;
+	union nf_inet_addr newaddr;
 	u_int16_t port;
 	unsigned int ret;
 
 	/* Reply comes from server. */
+	newaddr = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3;
+
 	exp->saved_proto.tcp.port = exp->tuple.dst.u.tcp.port;
 	exp->dir = IP_CT_DIR_REPLY;
 	exp->expectfn = nf_nat_follow_master;
@@ -57,17 +61,35 @@
 	}
 
 	if (port == 0) {
-		nf_ct_helper_log(skb, exp->master, "all ports in use");
+		nf_ct_helper_log(skb, ct, "all ports in use");
 		return NF_DROP;
 	}
 
-	ret = nf_nat_mangle_tcp_packet(skb, exp->master, ctinfo,
-				       protoff, matchoff, matchlen, buffer,
-				       strlen(buffer));
+	/* strlen("\1DCC CHAT chat AAAAAAAA P\1\n")=27
+	 * strlen("\1DCC SCHAT chat AAAAAAAA P\1\n")=28
+	 * strlen("\1DCC SEND F AAAAAAAA P S\1\n")=26
+	 * strlen("\1DCC MOVE F AAAAAAAA P S\1\n")=26
+	 * strlen("\1DCC TSEND F AAAAAAAA P S\1\n")=27
+	 *
+	 * AAAAAAAAA: bound addr (1.0.0.0==16777216, min 8 digits,
+	 *                        255.255.255.255==4294967296, 10 digits)
+	 * P:         bound port (min 1 d, max 5d (65635))
+	 * F:         filename   (min 1 d )
+	 * S:         size       (min 1 d )
+	 * 0x01, \n:  terminators
+	 */
+	/* AAA = "us", ie. where server normally talks to. */
+	snprintf(buffer, sizeof(buffer), "%u %u", ntohl(newaddr.ip), port);
+	pr_debug("nf_nat_irc: inserting '%s' == %pI4, port %u\n",
+		 buffer, &newaddr.ip, port);
+
+	ret = nf_nat_mangle_tcp_packet(skb, ct, ctinfo, protoff, matchoff,
+				       matchlen, buffer, strlen(buffer));
 	if (ret != NF_ACCEPT) {
-		nf_ct_helper_log(skb, exp->master, "cannot mangle packet");
+		nf_ct_helper_log(skb, ct, "cannot mangle packet");
 		nf_ct_unexpect_related(exp);
 	}
+
 	return ret;
 }
 
```
