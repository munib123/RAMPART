# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5021_8
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5021_8`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 716-756 of the vulnerable file.

				csum_partial_copy_nocheck(rfv->c + offset,
							  to, copy, 0),
				odd);

		odd = 0;
		offset += copy;
		to += copy;
		len -= copy;

		if (!len)
			return 0;
	}

	offset -= rfv->hlen;

	return ip_generic_getfrag(rfv->msg, to, offset, len, odd, skb);
}

static int rawv6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct ipv6_txoptions opt_space;
	DECLARE_SOCKADDR(struct sockaddr_in6 *, sin6, msg->msg_name);
	struct in6_addr *daddr, *final_p, final;
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct raw6_sock *rp = raw6_sk(sk);
	struct ipv6_txoptions *opt = NULL;
	struct ip6_flowlabel *flowlabel = NULL;
	struct dst_entry *dst = NULL;
	struct raw6_frag_vec rfv;
	struct flowi6 fl6;
	int addr_len = msg->msg_namelen;
	int hlimit = -1;
	int tclass = -1;
	int dontfrag = -1;
	u16 proto;
	int err;

	/* Rough check on arithmetic overflow,
	   better check is made in ip6_append_data().
	 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -733,6 +733,7 @@
 
 static int rawv6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
 {
+	struct ipv6_txoptions *opt_to_free = NULL;
 	struct ipv6_txoptions opt_space;
 	DECLARE_SOCKADDR(struct sockaddr_in6 *, sin6, msg->msg_name);
 	struct in6_addr *daddr, *final_p, final;
@@ -839,8 +840,10 @@
 		if (!(opt->opt_nflen|opt->opt_flen))
 			opt = NULL;
 	}
-	if (!opt)
-		opt = np->opt;
+	if (!opt) {
+		opt = txopt_get(np);
+		opt_to_free = opt;
+		}
 	if (flowlabel)
 		opt = fl6_merge_options(&opt_space, flowlabel, opt);
 	opt = ipv6_fixup_options(&opt_space, opt);
@@ -906,6 +909,7 @@
 	dst_release(dst);
 out:
 	fl6_sock_release(flowlabel);
+	txopt_put(opt_to_free);
 	return err < 0 ? err : len;
 do_confirm:
 	dst_confirm(dst);
```
