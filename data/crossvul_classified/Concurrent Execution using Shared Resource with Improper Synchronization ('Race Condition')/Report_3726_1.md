# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3726_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3726_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 35-75 of the vulnerable file.


struct inet_skb_parm {
	struct ip_options	opt;		/* Compiled IP options		*/
	unsigned char		flags;

#define IPSKB_FORWARDED		1
#define IPSKB_XFRM_TUNNEL_SIZE	2
#define IPSKB_XFRM_TRANSFORMED	4
#define IPSKB_FRAG_COMPLETE	8
#define IPSKB_REROUTED		16
};

static inline unsigned int ip_hdrlen(const struct sk_buff *skb)
{
	return ip_hdr(skb)->ihl * 4;
}

struct ipcm_cookie {
	__be32			addr;
	int			oif;
	struct ip_options	*opt;
	__u8			tx_flags;
};

#define IPCB(skb) ((struct inet_skb_parm*)((skb)->cb))

struct ip_ra_chain {
	struct ip_ra_chain __rcu *next;
	struct sock		*sk;
	union {
		void			(*destructor)(struct sock *);
		struct sock		*saved_sk;
	};
	struct rcu_head		rcu;
};

extern struct ip_ra_chain __rcu *ip_ra_chain;

/* IP flags. */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,7 +52,7 @@
 struct ipcm_cookie {
 	__be32			addr;
 	int			oif;
-	struct ip_options	*opt;
+	struct ip_options_rcu	*opt;
 	__u8			tx_flags;
 };
 
@@ -92,7 +92,7 @@
 
 extern int		ip_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
 					      __be32 saddr, __be32 daddr,
-					      struct ip_options *opt);
+					      struct ip_options_rcu *opt);
 extern int		ip_rcv(struct sk_buff *skb, struct net_device *dev,
 			       struct packet_type *pt, struct net_device *orig_dev);
 extern int		ip_local_deliver(struct sk_buff *skb);
@@ -416,14 +416,15 @@
  *	Functions provided by ip_options.c
  */
  
-extern void ip_options_build(struct sk_buff *skb, struct ip_options *opt, __be32 daddr, struct rtable *rt, int is_frag);
+extern void ip_options_build(struct sk_buff *skb, struct ip_options *opt,
+			     __be32 daddr, struct rtable *rt, int is_frag);
 extern int ip_options_echo(struct ip_options *dopt, struct sk_buff *skb);
 extern void ip_options_fragment(struct sk_buff *skb);
 extern int ip_options_compile(struct net *net,
 			      struct ip_options *opt, struct sk_buff *skb);
-extern int ip_options_get(struct net *net, struct ip_options **optp,
+extern int ip_options_get(struct net *net, struct ip_options_rcu **optp,
 			  unsigned char *data, int optlen);
-extern int ip_options_get_from_user(struct net *net, struct ip_options **optp,
+extern int ip_options_get_from_user(struct net *net, struct ip_options_rcu **optp,
 				    unsigned char __user *data, int optlen);
 extern void ip_options_undo(struct ip_options * opt);
 extern void ip_forward_options(struct sk_buff *skb);
```
