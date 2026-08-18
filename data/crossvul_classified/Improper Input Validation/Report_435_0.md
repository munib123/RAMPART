# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 435_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `435_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 957-1000 of the vulnerable file.

			goto out;

		if ((new_map.nr_extents + 1) == UID_GID_MAP_MAX_EXTENTS &&
		    (next_line != NULL))
			goto out;

		ret = insert_extent(&new_map, &extent);
		if (ret < 0)
			goto out;
		ret = -EINVAL;
	}
	/* Be very certaint the new map actually exists */
	if (new_map.nr_extents == 0)
		goto out;

	ret = -EPERM;
	/* Validate the user is allowed to use user id's mapped to. */
	if (!new_idmap_permitted(file, ns, cap_setid, &new_map))
		goto out;

	ret = sort_idmaps(&new_map);
	if (ret < 0)
		goto out;

	ret = -EPERM;
	/* Map the lower ids from the parent user namespace to the
	 * kernel global id space.
	 */
	for (idx = 0; idx < new_map.nr_extents; idx++) {
		struct uid_gid_extent *e;
		u32 lower_first;

		if (new_map.nr_extents <= UID_GID_MAP_MAX_BASE_EXTENTS)
			e = &new_map.extent[idx];
		else
			e = &new_map.forward[idx];

		lower_first = map_id_range_down(parent_map,
						e->lower_first,
						e->count);

		/* Fail if we can not map the specified extent to
		 * the kernel global id space.
		 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -974,10 +974,6 @@
 	if (!new_idmap_permitted(file, ns, cap_setid, &new_map))
 		goto out;
 
-	ret = sort_idmaps(&new_map);
-	if (ret < 0)
-		goto out;
-
 	ret = -EPERM;
 	/* Map the lower ids from the parent user namespace to the
 	 * kernel global id space.
@@ -1003,6 +999,14 @@
 
 		e->lower_first = lower_first;
 	}
+
+	/*
+	 * If we want to use binary search for lookup, this clones the extent
+	 * array and sorts both copies.
+	 */
+	ret = sort_idmaps(&new_map);
+	if (ret < 0)
+		goto out;
 
 	/* Install the map */
 	if (new_map.nr_extents <= UID_GID_MAP_MAX_BASE_EXTENTS) {
```
