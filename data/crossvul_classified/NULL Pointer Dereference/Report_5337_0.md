# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5337_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5337_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 507-547 of the vulnerable file.

	edit->segment_cache[ASSOC_ARRAY_FAN_OUT] = result->terminal_node.slot;

	pr_devel("-->%s()\n", __func__);

	/* We arrived at a node which doesn't have an onward node or shortcut
	 * pointer that we have to follow.  This means that (a) the leaf we
	 * want must go here (either by insertion or replacement) or (b) we
	 * need to split this node and insert in one of the fragments.
	 */
	free_slot = -1;

	/* Firstly, we have to check the leaves in this node to see if there's
	 * a matching one we should replace in place.
	 */
	for (i = 0; i < ASSOC_ARRAY_FAN_OUT; i++) {
		ptr = node->slots[i];
		if (!ptr) {
			free_slot = i;
			continue;
		}
		if (ops->compare_object(assoc_array_ptr_to_leaf(ptr), index_key)) {
			pr_devel("replace in slot %d\n", i);
			edit->leaf_p = &node->slots[i];
			edit->dead_leaf = node->slots[i];
			pr_devel("<--%s() = ok [replace]\n", __func__);
			return true;
		}
	}

	/* If there is a free slot in this node then we can just insert the
	 * leaf here.
	 */
	if (free_slot >= 0) {
		pr_devel("insert in free slot %d\n", free_slot);
		edit->leaf_p = &node->slots[free_slot];
		edit->adjust_count_on = node;
		pr_devel("<--%s() = ok [insert]\n", __func__);
		return true;
	}

	/* The node has no spare slots - so we're either going to have to split
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -524,7 +524,9 @@
 			free_slot = i;
 			continue;
 		}
-		if (ops->compare_object(assoc_array_ptr_to_leaf(ptr), index_key)) {
+		if (assoc_array_ptr_is_leaf(ptr) &&
+		    ops->compare_object(assoc_array_ptr_to_leaf(ptr),
+					index_key)) {
 			pr_devel("replace in slot %d\n", i);
 			edit->leaf_p = &node->slots[i];
 			edit->dead_leaf = node->slots[i];
```
