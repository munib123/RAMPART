# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1266_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1266_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 159-199 of the vulnerable file.


	list_for_each_entry(iter, &alink->dscp_map, list)
		if (iter->handle == knode->handle) {
			list_del(&iter->list);
			kfree(iter);
			nfp_abm_update_band_map(alink);
			return;
		}
}

static int
nfp_abm_u32_knode_replace(struct nfp_abm_link *alink,
			  struct tc_cls_u32_knode *knode,
			  __be16 proto, struct netlink_ext_ack *extack)
{
	struct nfp_abm_u32_match *match = NULL, *iter;
	unsigned int tos_off;
	u8 mask, val;
	int err;

	if (!nfp_abm_u32_check_knode(alink->abm, knode, proto, extack))
		goto err_delete;

	tos_off = proto == htons(ETH_P_IP) ? 16 : 20;

	/* Extract the DSCP Class Selector bits */
	val = be32_to_cpu(knode->sel->keys[0].val) >> tos_off & 0xff;
	mask = be32_to_cpu(knode->sel->keys[0].mask) >> tos_off & 0xff;

	/* Check if there is no conflicting mapping and find match by handle */
	list_for_each_entry(iter, &alink->dscp_map, list) {
		u32 cmask;

		if (iter->handle == knode->handle) {
			match = iter;
			continue;
		}

		cmask = iter->mask & mask;
		if ((iter->val & cmask) == (val & cmask) &&
		    iter->band != knode->res->classid) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -176,8 +176,10 @@
 	u8 mask, val;
 	int err;
 
-	if (!nfp_abm_u32_check_knode(alink->abm, knode, proto, extack))
+	if (!nfp_abm_u32_check_knode(alink->abm, knode, proto, extack)) {
+		err = -EOPNOTSUPP;
 		goto err_delete;
+	}
 
 	tos_off = proto == htons(ETH_P_IP) ? 16 : 20;
 
@@ -198,14 +200,18 @@
 		if ((iter->val & cmask) == (val & cmask) &&
 		    iter->band != knode->res->classid) {
 			NL_SET_ERR_MSG_MOD(extack, "conflict with already offloaded filter");
+			err = -EOPNOTSUPP;
 			goto err_delete;
 		}
 	}
 
 	if (!match) {
 		match = kzalloc(sizeof(*match), GFP_KERNEL);
-		if (!match)
-			return -ENOMEM;
+		if (!match) {
+			err = -ENOMEM;
+			goto err_delete;
+		}
+
 		list_add(&match->list, &alink->dscp_map);
 	}
 	match->handle = knode->handle;
@@ -221,7 +227,7 @@
 
 err_delete:
 	nfp_abm_u32_knode_delete(alink, knode);
-	return -EOPNOTSUPP;
+	return err;
 }
 
 static int nfp_abm_setup_tc_block_cb(enum tc_setup_type type,
```
