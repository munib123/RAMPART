# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 1482_0
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1482_0`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 22-66 of the vulnerable file.

#ifndef _IP_H
#define _IP_H

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/skbuff.h>

#include <net/inet_sock.h>
#include <net/route.h>
#include <net/snmp.h>
#include <net/flow.h>
#include <net/flow_keys.h>

struct sock;

struct inet_skb_parm {
	struct ip_options	opt;		/* Compiled IP options		*/
	unsigned char		flags;

#define IPSKB_FORWARDED		1
#define IPSKB_XFRM_TUNNEL_SIZE	2
#define IPSKB_XFRM_TRANSFORMED	4
#define IPSKB_FRAG_COMPLETE	8
#define IPSKB_REROUTED		16

	u16			frag_max_size;
};

static inline unsigned int ip_hdrlen(const struct sk_buff *skb)
{
	return ip_hdr(skb)->ihl * 4;
}

struct ipcm_cookie {
	__be32			addr;
	int			oif;
	struct ip_options_rcu	*opt;
	__u8			tx_flags;
	__u8			ttl;
	__s16			tos;
	char			priority;
};

#define IPCB(skb) ((struct inet_skb_parm*)((skb)->cb))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,11 +39,12 @@
 	struct ip_options	opt;		/* Compiled IP options		*/
 	unsigned char		flags;
 
-#define IPSKB_FORWARDED		1
-#define IPSKB_XFRM_TUNNEL_SIZE	2
-#define IPSKB_XFRM_TRANSFORMED	4
-#define IPSKB_FRAG_COMPLETE	8
-#define IPSKB_REROUTED		16
+#define IPSKB_FORWARDED		BIT(0)
+#define IPSKB_XFRM_TUNNEL_SIZE	BIT(1)
+#define IPSKB_XFRM_TRANSFORMED	BIT(2)
+#define IPSKB_FRAG_COMPLETE	BIT(3)
+#define IPSKB_REROUTED		BIT(4)
+#define IPSKB_DOREDIRECT	BIT(5)
 
 	u16			frag_max_size;
 };
```
