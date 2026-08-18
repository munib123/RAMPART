# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2490_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2490_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1411-1451 of the vulnerable file.

  if (guard->pb.path_bias_disabled)
    return 0;

  if (gs->type == GS_TYPE_BRIDGE) {
    const bridge_info_t *bridge = get_bridge_info_for_guard(guard);
    if (bridge == NULL)
      return 0;
    return bridge_passes_guard_filter(options, bridge);
  } else {
    const node_t *node = node_get_by_id(guard->identity);
    if (node == NULL) {
      // This can happen when currently_listed is true, and we're not updating
      // it because we don't have a live consensus.
      return 0;
    }

    return node_passes_guard_filter(options, node);
  }
}

/**
 * Return true iff <b>guard</b> obeys the restrictions defined in <b>rst</b>.
 * (If <b>rst</b> is NULL, there are no restrictions.)
 */
static int
entry_guard_obeys_restriction(const entry_guard_t *guard,
                              const entry_guard_restriction_t *rst)
{
  tor_assert(guard);
  if (! rst)
    return 1; // No restriction?  No problem.

  // Only one kind of restriction exists right now
  return tor_memneq(guard->identity, rst->exclude_id, DIGEST_LEN);
}

/**
 * Update the <b>is_filtered_guard</b> and <b>is_usable_filtered_guard</b>
 * flags on <b>guard</b>. */
void
entry_guard_set_filtered_flags(const or_options_t *options,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1428,6 +1428,38 @@
   }
 }
 
+/** Return true iff <b>guard</b> is in the same family as <b>node</b>.
+ */
+static int
+guard_in_node_family(const entry_guard_t *guard, const node_t *node)
+{
+  const node_t *guard_node = node_get_by_id(guard->identity);
+  if (guard_node) {
+    return nodes_in_same_family(guard_node, node);
+  } else {
+    /* If we don't have a node_t for the guard node, we might have
+     * a bridge_info_t for it. So let's check to see whether the bridge
+     * address matches has any family issues.
+     *
+     * (Strictly speaking, I believe this check is unnecessary, since we only
+     * use it to avoid the exit's family when building circuits, and we don't
+     * build multihop circuits until we have a routerinfo_t for the
+     * bridge... at which point, we'll also have a node_t for the
+     * bridge. Nonetheless, it seems wise to include it, in case our
+     * assumptions change down the road.  -nickm.)
+     */
+    if (get_options()->EnforceDistinctSubnets && guard->bridge_addr) {
+      tor_addr_t node_addr;
+      node_get_addr(node, &node_addr);
+      if (addrs_in_same_network_family(&node_addr,
+                                       &guard->bridge_addr->addr)) {
+        return 1;
+      }
+    }
+    return 0;
+  }
+}
+
 /**
  * Return true iff <b>guard</b> obeys the restrictions defined in <b>rst</b>.
  * (If <b>rst</b> is NULL, there are no restrictions.)
@@ -1440,7 +1472,12 @@
   if (! rst)
     return 1; // No restriction?  No problem.
 
-  // Only one kind of restriction exists right now
+  // Only one kind of restriction exists right now: excluding an exit
+  // ID and all of its family.
+  const node_t *node = node_get_by_id((const char*)rst->exclude_id);
+  if (node && guard_in_node_family(guard, node))
+    return 0;
+
   return tor_memneq(guard->identity, rst->exclude_id, DIGEST_LEN);
 }
 
```
