# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5021_7
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5021_7`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 94-134 of the vulnerable file.

	new_ra->next = ra;
	*rap = new_ra;
	sock_hold(sk);
	write_unlock_bh(&ip6_ra_lock);
	return 0;
}

static
struct ipv6_txoptions *ipv6_update_options(struct sock *sk,
					   struct ipv6_txoptions *opt)
{
	if (inet_sk(sk)->is_icsk) {
		if (opt &&
		    !((1 << sk->sk_state) & (TCPF_LISTEN | TCPF_CLOSE)) &&
		    inet_sk(sk)->inet_daddr != LOOPBACK4_IPV6) {
			struct inet_connection_sock *icsk = inet_csk(sk);
			icsk->icsk_ext_hdr_len = opt->opt_flen + opt->opt_nflen;
			icsk->icsk_sync_mss(sk, icsk->icsk_pmtu_cookie);
		}
	}
	opt = xchg(&inet6_sk(sk)->opt, opt);
	sk_dst_reset(sk);

	return opt;
}

static bool setsockopt_needs_rtnl(int optname)
{
	switch (optname) {
	case IPV6_ADD_MEMBERSHIP:
	case IPV6_DROP_MEMBERSHIP:
	case IPV6_JOIN_ANYCAST:
	case IPV6_LEAVE_ANYCAST:
	case MCAST_JOIN_GROUP:
	case MCAST_LEAVE_GROUP:
	case MCAST_JOIN_SOURCE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
	case MCAST_MSFILTER:
		return true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -111,7 +111,8 @@
 			icsk->icsk_sync_mss(sk, icsk->icsk_pmtu_cookie);
 		}
 	}
-	opt = xchg(&inet6_sk(sk)->opt, opt);
+	opt = xchg((__force struct ipv6_txoptions **)&inet6_sk(sk)->opt,
+		   opt);
 	sk_dst_reset(sk);
 
 	return opt;
@@ -231,9 +232,12 @@
 				sk->sk_socket->ops = &inet_dgram_ops;
 				sk->sk_family = PF_INET;
 			}
-			opt = xchg(&np->opt, NULL);
-			if (opt)
-				sock_kfree_s(sk, opt, opt->tot_len);
+			opt = xchg((__force struct ipv6_txoptions **)&np->opt,
+				   NULL);
+			if (opt) {
+				atomic_sub(opt->tot_len, &sk->sk_omem_alloc);
+				txopt_put(opt);
+			}
 			pktopt = xchg(&np->pktoptions, NULL);
 			kfree_skb(pktopt);
 
@@ -403,7 +407,8 @@
 		if (optname != IPV6_RTHDR && !ns_capable(net->user_ns, CAP_NET_RAW))
 			break;
 
-		opt = ipv6_renew_options(sk, np->opt, optname,
+		opt = rcu_dereference_protected(np->opt, sock_owned_by_user(sk));
+		opt = ipv6_renew_options(sk, opt, optname,
 					 (struct ipv6_opt_hdr __user *)optval,
 					 optlen);
 		if (IS_ERR(opt)) {
@@ -432,8 +437,10 @@
 		retv = 0;
 		opt = ipv6_update_options(sk, opt);
 sticky_done:
-		if (opt)
-			sock_kfree_s(sk, opt, opt->tot_len);
+		if (opt) {
+			atomic_sub(opt->tot_len, &sk->sk_omem_alloc);
+			txopt_put(opt);
+		}
 		break;
 	}
 
@@ -486,6 +493,7 @@
 			break;
 
 		memset(opt, 0, sizeof(*opt));
+		atomic_set(&opt->refcnt, 1);
 		opt->tot_len = sizeof(*opt) + optlen;
 		retv = -EFAULT;
 		if (copy_from_user(opt+1, optval, optlen))
@@ -502,8 +510,10 @@
 		retv = 0;
 		opt = ipv6_update_options(sk, opt);
 done:
-		if (opt)
-			sock_kfree_s(sk, opt, opt->tot_len);
+		if (opt) {
+			atomic_sub(opt->tot_len, &sk->sk_omem_alloc);
+			txopt_put(opt);
+		}
 		break;
 	}
 	case IPV6_UNICAST_HOPS:
@@ -1110,10 +1120,11 @@
 	case IPV6_RTHDR:
 	case IPV6_DSTOPTS:
 	{
+		struct ipv6_txoptions *opt;
 
 		lock_sock(sk);
-		len = ipv6_getsockopt_sticky(sk, np->opt,
-					     optname, optval, len);
+		opt = rcu_dereference_protected(np->opt, sock_owned_by_user(sk));
+		len = ipv6_getsockopt_sticky(sk, opt, optname, optval, len);
 		release_sock(sk);
 		/* check if ipv6_getsockopt_sticky() returns err code */
 		if (len < 0)
```
