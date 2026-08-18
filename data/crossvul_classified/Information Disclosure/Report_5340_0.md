# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5340_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5340_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 311-354 of the vulnerable file.

#endif
		{
			nfnl_unlock(subsys_id);
			netlink_ack(oskb, nlh, -EOPNOTSUPP);
			return kfree_skb(skb);
		}
	}

	if (!ss->commit || !ss->abort) {
		nfnl_unlock(subsys_id);
		netlink_ack(oskb, nlh, -EOPNOTSUPP);
		return kfree_skb(skb);
	}

	while (skb->len >= nlmsg_total_size(0)) {
		int msglen, type;

		nlh = nlmsg_hdr(skb);
		err = 0;

		if (nlmsg_len(nlh) < sizeof(struct nfgenmsg) ||
		    skb->len < nlh->nlmsg_len) {
			err = -EINVAL;
			goto ack;
		}

		/* Only requests are handled by the kernel */
		if (!(nlh->nlmsg_flags & NLM_F_REQUEST)) {
			err = -EINVAL;
			goto ack;
		}

		type = nlh->nlmsg_type;
		if (type == NFNL_MSG_BATCH_BEGIN) {
			/* Malformed: Batch begin twice */
			nfnl_err_reset(&err_list);
			status |= NFNL_BATCH_FAILURE;
			goto done;
		} else if (type == NFNL_MSG_BATCH_END) {
			status |= NFNL_BATCH_DONE;
			goto done;
		} else if (type < NLMSG_MIN_TYPE) {
			err = -EINVAL;
			goto ack;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -328,10 +328,12 @@
 		nlh = nlmsg_hdr(skb);
 		err = 0;
 
-		if (nlmsg_len(nlh) < sizeof(struct nfgenmsg) ||
-		    skb->len < nlh->nlmsg_len) {
-			err = -EINVAL;
-			goto ack;
+		if (nlh->nlmsg_len < NLMSG_HDRLEN ||
+		    skb->len < nlh->nlmsg_len ||
+		    nlmsg_len(nlh) < sizeof(struct nfgenmsg)) {
+			nfnl_err_reset(&err_list);
+			status |= NFNL_BATCH_FAILURE;
+			goto done;
 		}
 
 		/* Only requests are handled by the kernel */
```
