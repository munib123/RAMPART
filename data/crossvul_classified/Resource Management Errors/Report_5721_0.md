# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5721_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5721_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 164-204 of the vulnerable file.


extern void udp_lib_unhash(struct sock *sk);
extern void udp_lib_rehash(struct sock *sk, u16 new_hash);

static inline void udp_lib_close(struct sock *sk, long timeout)
{
	sk_common_release(sk);
}

extern int udp_lib_get_port(struct sock *sk, unsigned short snum,
			    int (*)(const struct sock *,const struct sock *),
			    unsigned int hash2_nulladdr);

/* net/ipv4/udp.c */
extern int udp_get_port(struct sock *sk, unsigned short snum,
			int (*saddr_cmp)(const struct sock *,
					 const struct sock *));
extern void udp_err(struct sk_buff *, u32);
extern int udp_sendmsg(struct kiocb *iocb, struct sock *sk,
			    struct msghdr *msg, size_t len);
extern void udp_flush_pending_frames(struct sock *sk);
extern int udp_rcv(struct sk_buff *skb);
extern int udp_ioctl(struct sock *sk, int cmd, unsigned long arg);
extern int udp_disconnect(struct sock *sk, int flags);
extern unsigned int udp_poll(struct file *file, struct socket *sock,
			     poll_table *wait);
extern struct sk_buff *skb_udp_tunnel_segment(struct sk_buff *skb,
					      netdev_features_t features);
extern int udp_lib_getsockopt(struct sock *sk, int level, int optname,
			      char __user *optval, int __user *optlen);
extern int udp_lib_setsockopt(struct sock *sk, int level, int optname,
			      char __user *optval, unsigned int optlen,
			      int (*push_pending_frames)(struct sock *));
extern struct sock *udp4_lib_lookup(struct net *net, __be32 saddr, __be16 sport,
				    __be32 daddr, __be16 dport,
				    int dif);
extern struct sock *__udp4_lib_lookup(struct net *net, __be32 saddr, __be16 sport,
				    __be32 daddr, __be16 dport,
				    int dif, struct udp_table *tbl);
extern struct sock *udp6_lib_lookup(struct net *net, const struct in6_addr *saddr, __be16 sport,
				    const struct in6_addr *daddr, __be16 dport,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -181,6 +181,7 @@
 extern void udp_err(struct sk_buff *, u32);
 extern int udp_sendmsg(struct kiocb *iocb, struct sock *sk,
 			    struct msghdr *msg, size_t len);
+extern int udp_push_pending_frames(struct sock *sk);
 extern void udp_flush_pending_frames(struct sock *sk);
 extern int udp_rcv(struct sk_buff *skb);
 extern int udp_ioctl(struct sock *sk, int cmd, unsigned long arg);
```
