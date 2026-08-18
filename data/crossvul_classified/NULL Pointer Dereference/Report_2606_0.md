# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2606_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2606_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 581-622 of the vulnerable file.

	if (have_meta) {
		pr_devel("have meta\n");
		goto split_node;
	}

	/* The node contains only leaves */
	dissimilarity = 0;
	base_seg = edit->segment_cache[0];
	for (i = 1; i < ASSOC_ARRAY_FAN_OUT; i++)
		dissimilarity |= edit->segment_cache[i] ^ base_seg;

	pr_devel("only leaves; dissimilarity=%lx\n", dissimilarity);

	if ((dissimilarity & ASSOC_ARRAY_FAN_MASK) == 0) {
		/* The old leaves all cluster in the same slot.  We will need
		 * to insert a shortcut if the new node wants to cluster with them.
		 */
		if ((edit->segment_cache[ASSOC_ARRAY_FAN_OUT] ^ base_seg) == 0)
			goto all_leaves_cluster_together;

		/* Otherwise we can just insert a new node ahead of the old
		 * one.
		 */
		goto present_leaves_cluster_but_not_new_leaf;
	}

split_node:
	pr_devel("split node\n");

	/* We need to split the current node; we know that the node doesn't
	 * simply contain a full set of leaves that cluster together (it
	 * contains meta pointers and/or non-clustering leaves).
	 *
	 * We need to expel at least two leaves out of a set consisting of the
	 * leaves in the node and the new leaf.
	 *
	 * We need a new node (n0) to replace the current one and a new node to
	 * take the expelled nodes (n1).
	 */
	edit->set[0].to = assoc_array_node_to_ptr(new_n0);
	new_n0->back_pointer = node->back_pointer;
	new_n0->parent_slot = node->parent_slot;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -598,21 +598,31 @@
 		if ((edit->segment_cache[ASSOC_ARRAY_FAN_OUT] ^ base_seg) == 0)
 			goto all_leaves_cluster_together;
 
-		/* Otherwise we can just insert a new node ahead of the old
-		 * one.
+		/* Otherwise all the old leaves cluster in the same slot, but
+		 * the new leaf wants to go into a different slot - so we
+		 * create a new node (n0) to hold the new leaf and a pointer to
+		 * a new node (n1) holding all the old leaves.
+		 *
+		 * This can be done by falling through to the node splitting
+		 * path.
 		 */
-		goto present_leaves_cluster_but_not_new_leaf;
+		pr_devel("present leaves cluster but not new leaf\n");
 	}
 
 split_node:
 	pr_devel("split node\n");
 
-	/* We need to split the current node; we know that the node doesn't
-	 * simply contain a full set of leaves that cluster together (it
-	 * contains meta pointers and/or non-clustering leaves).
+	/* We need to split the current node.  The node must contain anything
+	 * from a single leaf (in the one leaf case, this leaf will cluster
+	 * with the new leaf) and the rest meta-pointers, to all leaves, some
+	 * of which may cluster.
+	 *
+	 * It won't contain the case in which all the current leaves plus the
+	 * new leaves want to cluster in the same slot.
 	 *
 	 * We need to expel at least two leaves out of a set consisting of the
-	 * leaves in the node and the new leaf.
+	 * leaves in the node and the new leaf.  The current meta pointers can
+	 * just be copied as they shouldn't cluster with any of the leaves.
 	 *
 	 * We need a new node (n0) to replace the current one and a new node to
 	 * take the expelled nodes (n1).
@@ -715,33 +725,6 @@
 		edit->set[0].ptr = &assoc_array_ptr_to_shortcut(ptr)->next_node;
 	edit->excised_meta[0] = assoc_array_node_to_ptr(node);
 	pr_devel("<--%s() = ok [split node]\n", __func__);
-	return true;
-
-present_leaves_cluster_but_not_new_leaf:
-	/* All the old leaves cluster in the same slot, but the new leaf wants
-	 * to go into a different slot, so we create a new node to hold the new
-	 * leaf and a pointer to a new node holding all the old leaves.
-	 */
-	pr_devel("present leaves cluster but not new leaf\n");
-
-	new_n0->back_pointer = node->back_pointer;
-	new_n0->parent_slot = node->parent_slot;
-	new_n0->nr_leaves_on_branch = node->nr_leaves_on_branch;
-	new_n1->back_pointer = assoc_array_node_to_ptr(new_n0);
-	new_n1->parent_slot = edit->segment_cache[0];
-	new_n1->nr_leaves_on_branch = node->nr_leaves_on_branch;
-	edit->adjust_count_on = new_n0;
-
-	for (i = 0; i < ASSOC_ARRAY_FAN_OUT; i++)
-		new_n1->slots[i] = node->slots[i];
-
-	new_n0->slots[edit->segment_cache[0]] = assoc_array_node_to_ptr(new_n0);
-	edit->leaf_p = &new_n0->slots[edit->segment_cache[ASSOC_ARRAY_FAN_OUT]];
-
-	edit->set[0].ptr = &assoc_array_ptr_to_node(node->back_pointer)->slots[node->parent_slot];
-	edit->set[0].to = assoc_array_node_to_ptr(new_n0);
-	edit->excised_meta[0] = assoc_array_node_to_ptr(node);
-	pr_devel("<--%s() = ok [insert node before]\n", __func__);
 	return true;
 
 all_leaves_cluster_together:
```
