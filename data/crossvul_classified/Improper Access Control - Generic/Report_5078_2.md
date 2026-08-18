# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5078_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5078_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 737-777 of the vulnerable file.

	unsigned int h;
	int err;

	if ((unsigned long)e % __alignof__(struct ipt_entry) != 0 ||
	    (unsigned char *)e + sizeof(struct ipt_entry) >= limit ||
	    (unsigned char *)e + e->next_offset > limit) {
		duprintf("Bad offset %p\n", e);
		return -EINVAL;
	}

	if (e->next_offset
	    < sizeof(struct ipt_entry) + sizeof(struct xt_entry_target)) {
		duprintf("checking: element %p size %u\n",
			 e, e->next_offset);
		return -EINVAL;
	}

	if (!ip_checkentry(&e->ip))
		return -EINVAL;

	err = xt_check_entry_offsets(e, e->target_offset, e->next_offset);
	if (err)
		return err;

	/* Check hooks & underflows */
	for (h = 0; h < NF_INET_NUMHOOKS; h++) {
		if (!(valid_hooks & (1 << h)))
			continue;
		if ((unsigned char *)e - base == hook_entries[h])
			newinfo->hook_entry[h] = hook_entries[h];
		if ((unsigned char *)e - base == underflows[h]) {
			if (!check_underflow(e)) {
				pr_debug("Underflows must be unconditional and "
					 "use the STANDARD target with "
					 "ACCEPT/DROP\n");
				return -EINVAL;
			}
			newinfo->underflow[h] = underflows[h];
		}
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -754,7 +754,8 @@
 	if (!ip_checkentry(&e->ip))
 		return -EINVAL;
 
-	err = xt_check_entry_offsets(e, e->target_offset, e->next_offset);
+	err = xt_check_entry_offsets(e, e->elems, e->target_offset,
+				     e->next_offset);
 	if (err)
 		return err;
 
@@ -1513,7 +1514,7 @@
 	if (!ip_checkentry(&e->ip))
 		return -EINVAL;
 
-	ret = xt_compat_check_entry_offsets(e,
+	ret = xt_compat_check_entry_offsets(e, e->elems,
 					    e->target_offset, e->next_offset);
 	if (ret)
 		return ret;
```
