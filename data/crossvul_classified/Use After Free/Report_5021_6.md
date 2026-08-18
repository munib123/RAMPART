# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5021_6
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5021_6`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 61-101 of the vulnerable file.

		}
	}

	return sk2 != NULL;
}
EXPORT_SYMBOL_GPL(inet6_csk_bind_conflict);

struct dst_entry *inet6_csk_route_req(const struct sock *sk,
				      struct flowi6 *fl6,
				      const struct request_sock *req,
				      u8 proto)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	const struct ipv6_pinfo *np = inet6_sk(sk);
	struct in6_addr *final_p, final;
	struct dst_entry *dst;

	memset(fl6, 0, sizeof(*fl6));
	fl6->flowi6_proto = proto;
	fl6->daddr = ireq->ir_v6_rmt_addr;
	final_p = fl6_update_dst(fl6, np->opt, &final);
	fl6->saddr = ireq->ir_v6_loc_addr;
	fl6->flowi6_oif = ireq->ir_iif;
	fl6->flowi6_mark = ireq->ir_mark;
	fl6->fl6_dport = ireq->ir_rmt_port;
	fl6->fl6_sport = htons(ireq->ir_num);
	security_req_classify_flow(req, flowi6_to_flowi(fl6));

	dst = ip6_dst_lookup_flow(sk, fl6, final_p);
	if (IS_ERR(dst))
		return NULL;

	return dst;
}
EXPORT_SYMBOL(inet6_csk_route_req);

void inet6_csk_addr2sockaddr(struct sock *sk, struct sockaddr *uaddr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) uaddr;

	sin6->sin6_family = AF_INET6;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,7 +78,9 @@
 	memset(fl6, 0, sizeof(*fl6));
 	fl6->flowi6_proto = proto;
 	fl6->daddr = ireq->ir_v6_rmt_addr;
-	final_p = fl6_update_dst(fl6, np->opt, &final);
+	rcu_read_lock();
+	final_p = fl6_update_dst(fl6, rcu_dereference(np->opt), &final);
+	rcu_read_unlock();
 	fl6->saddr = ireq->ir_v6_loc_addr;
 	fl6->flowi6_oif = ireq->ir_iif;
 	fl6->flowi6_mark = ireq->ir_mark;
@@ -142,7 +144,9 @@
 	fl6->fl6_dport = inet->inet_dport;
 	security_sk_classify_flow(sk, flowi6_to_flowi(fl6));
 
-	final_p = fl6_update_dst(fl6, np->opt, &final);
+	rcu_read_lock();
+	final_p = fl6_update_dst(fl6, rcu_dereference(np->opt), &final);
+	rcu_read_unlock();
 
 	dst = __inet6_csk_dst_check(sk, np->dst_cookie);
 	if (!dst) {
@@ -175,7 +179,8 @@
 	/* Restore final destination back after routing done */
 	fl6.daddr = sk->sk_v6_daddr;
 
-	res = ip6_xmit(sk, skb, &fl6, np->opt, np->tclass);
+	res = ip6_xmit(sk, skb, &fl6, rcu_dereference(np->opt),
+		       np->tclass);
 	rcu_read_unlock();
 	return res;
 }
```
