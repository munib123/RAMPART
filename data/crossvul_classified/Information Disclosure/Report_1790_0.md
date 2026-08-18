# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1790_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1790_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 402-442 of the vulnerable file.

	po = lookup_chan(htons(header->call_id), iph->saddr);
	if (po) {
		skb_dst_drop(skb);
		nf_reset(skb);
		return sk_receive_skb(sk_pppox(po), skb, 0);
	}
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int pptp_bind(struct socket *sock, struct sockaddr *uservaddr,
	int sockaddr_len)
{
	struct sock *sk = sock->sk;
	struct sockaddr_pppox *sp = (struct sockaddr_pppox *) uservaddr;
	struct pppox_sock *po = pppox_sk(sk);
	struct pptp_opt *opt = &po->proto.pptp;
	int error = 0;

	lock_sock(sk);

	opt->src_addr = sp->sa_addr.pptp;
	if (add_chan(po))
		error = -EBUSY;

	release_sock(sk);
	return error;
}

static int pptp_connect(struct socket *sock, struct sockaddr *uservaddr,
	int sockaddr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_pppox *sp = (struct sockaddr_pppox *) uservaddr;
	struct pppox_sock *po = pppox_sk(sk);
	struct pptp_opt *opt = &po->proto.pptp;
	struct rtable *rt;
	struct flowi4 fl4;
	int error = 0;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -419,6 +419,9 @@
 	struct pptp_opt *opt = &po->proto.pptp;
 	int error = 0;
 
+	if (sockaddr_len < sizeof(struct sockaddr_pppox))
+		return -EINVAL;
+
 	lock_sock(sk);
 
 	opt->src_addr = sp->sa_addr.pptp;
@@ -439,6 +442,9 @@
 	struct rtable *rt;
 	struct flowi4 fl4;
 	int error = 0;
+
+	if (sockaddr_len < sizeof(struct sockaddr_pppox))
+		return -EINVAL;
 
 	if (sp->sa_protocol != PX_PROTO_PPTP)
 		return -EINVAL;
```
