# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2986_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2986_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 3450-3492 of the vulnerable file.

{
	if (!(rold->live & REG_LIVE_READ))
		/* explored state didn't use this */
		return true;

	if (memcmp(rold, rcur, offsetof(struct bpf_reg_state, live)) == 0)
		return true;

	if (rold->type == NOT_INIT)
		/* explored state can't have used this */
		return true;
	if (rcur->type == NOT_INIT)
		return false;
	switch (rold->type) {
	case SCALAR_VALUE:
		if (rcur->type == SCALAR_VALUE) {
			/* new val must satisfy old val knowledge */
			return range_within(rold, rcur) &&
			       tnum_in(rold->var_off, rcur->var_off);
		} else {
			/* if we knew anything about the old value, we're not
			 * equal, because we can't know anything about the
			 * scalar value of the pointer in the new value.
			 */
			return rold->umin_value == 0 &&
			       rold->umax_value == U64_MAX &&
			       rold->smin_value == S64_MIN &&
			       rold->smax_value == S64_MAX &&
			       tnum_is_unknown(rold->var_off);
		}
	case PTR_TO_MAP_VALUE:
		/* If the new min/max/var_off satisfy the old ones and
		 * everything else matches, we are OK.
		 * We don't care about the 'id' value, because nothing
		 * uses it for PTR_TO_MAP_VALUE (only for ..._OR_NULL)
		 */
		return memcmp(rold, rcur, offsetof(struct bpf_reg_state, id)) == 0 &&
		       range_within(rold, rcur) &&
		       tnum_in(rold->var_off, rcur->var_off);
	case PTR_TO_MAP_VALUE_OR_NULL:
		/* a PTR_TO_MAP_VALUE could be safe to use as a
		 * PTR_TO_MAP_VALUE_OR_NULL into the same map.
		 * However, if the old PTR_TO_MAP_VALUE_OR_NULL then got NULL-
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3467,15 +3467,14 @@
 			return range_within(rold, rcur) &&
 			       tnum_in(rold->var_off, rcur->var_off);
 		} else {
-			/* if we knew anything about the old value, we're not
-			 * equal, because we can't know anything about the
-			 * scalar value of the pointer in the new value.
+			/* We're trying to use a pointer in place of a scalar.
+			 * Even if the scalar was unbounded, this could lead to
+			 * pointer leaks because scalars are allowed to leak
+			 * while pointers are not. We could make this safe in
+			 * special cases if root is calling us, but it's
+			 * probably not worth the hassle.
 			 */
-			return rold->umin_value == 0 &&
-			       rold->umax_value == U64_MAX &&
-			       rold->smin_value == S64_MIN &&
-			       rold->smax_value == S64_MAX &&
-			       tnum_is_unknown(rold->var_off);
+			return false;
 		}
 	case PTR_TO_MAP_VALUE:
 		/* If the new min/max/var_off satisfy the old ones and
```
