# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 1162_1
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1162_1`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 107-147 of the vulnerable file.


	ether_addr_copy(node->MacAddressA, addr_a);
	ether_addr_copy(node->MacAddressB, addr_b);

	rcu_read_lock();
	oldnode = list_first_or_null_rcu(self_node_db,
						struct hsr_node, mac_list);
	if (oldnode) {
		list_replace_rcu(&oldnode->mac_list, &node->mac_list);
		rcu_read_unlock();
		synchronize_rcu();
		kfree(oldnode);
	} else {
		rcu_read_unlock();
		list_add_tail_rcu(&node->mac_list, self_node_db);
	}

	return 0;
}


/* Allocate an hsr_node and add it to node_db. 'addr' is the node's AddressA;
 * seq_out is used to initialize filtering of outgoing duplicate frames
 * originating from the newly added node.
 */
struct hsr_node *hsr_add_node(struct list_head *node_db, unsigned char addr[],
			      u16 seq_out)
{
	struct hsr_node *node;
	unsigned long now;
	int i;

	node = kzalloc(sizeof(*node), GFP_ATOMIC);
	if (!node)
		return NULL;

	ether_addr_copy(node->MacAddressA, addr);

	/* We are only interested in time diffs here, so use current jiffies
	 * as initialization. (0 could trigger an spurious ring error warning).
	 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -124,6 +124,18 @@
 	return 0;
 }
 
+void hsr_del_node(struct list_head *self_node_db)
+{
+	struct hsr_node *node;
+
+	rcu_read_lock();
+	node = list_first_or_null_rcu(self_node_db, struct hsr_node, mac_list);
+	rcu_read_unlock();
+	if (node) {
+		list_del_rcu(&node->mac_list);
+		kfree(node);
+	}
+}
 
 /* Allocate an hsr_node and add it to node_db. 'addr' is the node's AddressA;
  * seq_out is used to initialize filtering of outgoing duplicate frames
```
