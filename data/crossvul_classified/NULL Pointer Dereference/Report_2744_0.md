# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2744_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2744_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 2746-2786 of the vulnerable file.

		if (err == 0 && rt->dst.error)
			err = -rt->dst.error;
	} else {
		rt = ip_route_output_key_hash_rcu(net, &fl4, &res, skb);
		err = 0;
		if (IS_ERR(rt))
			err = PTR_ERR(rt);
		else
			skb_dst_set(skb, &rt->dst);
	}

	if (err)
		goto errout_free;

	if (rtm->rtm_flags & RTM_F_NOTIFY)
		rt->rt_flags |= RTCF_NOTIFY;

	if (rtm->rtm_flags & RTM_F_LOOKUP_TABLE)
		table_id = rt->rt_table_id;

	if (rtm->rtm_flags & RTM_F_FIB_MATCH)
		err = fib_dump_info(skb, NETLINK_CB(in_skb).portid,
				    nlh->nlmsg_seq, RTM_NEWROUTE, table_id,
				    rt->rt_type, res.prefix, res.prefixlen,
				    fl4.flowi4_tos, res.fi, 0);
	else
		err = rt_fill_info(net, dst, src, table_id, &fl4, skb,
				   NETLINK_CB(in_skb).portid, nlh->nlmsg_seq);
	if (err < 0)
		goto errout_free;

	rcu_read_unlock();

	err = rtnl_unicast(skb, net, NETLINK_CB(in_skb).portid);
errout:
	return err;

errout_free:
	rcu_read_unlock();
	kfree_skb(skb);
	goto errout;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2763,14 +2763,21 @@
 	if (rtm->rtm_flags & RTM_F_LOOKUP_TABLE)
 		table_id = rt->rt_table_id;
 
-	if (rtm->rtm_flags & RTM_F_FIB_MATCH)
+	if (rtm->rtm_flags & RTM_F_FIB_MATCH) {
+		if (!res.fi) {
+			err = fib_props[res.type].error;
+			if (!err)
+				err = -EHOSTUNREACH;
+			goto errout_free;
+		}
 		err = fib_dump_info(skb, NETLINK_CB(in_skb).portid,
 				    nlh->nlmsg_seq, RTM_NEWROUTE, table_id,
 				    rt->rt_type, res.prefix, res.prefixlen,
 				    fl4.flowi4_tos, res.fi, 0);
-	else
+	} else {
 		err = rt_fill_info(net, dst, src, table_id, &fl4, skb,
 				   NETLINK_CB(in_skb).portid, nlh->nlmsg_seq);
+	}
 	if (err < 0)
 		goto errout_free;
 
```
