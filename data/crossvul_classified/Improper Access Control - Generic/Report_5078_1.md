# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5078_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5078_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 575-615 of the vulnerable file.

	unsigned int h;
	int err;

	if ((unsigned long)e % __alignof__(struct arpt_entry) != 0 ||
	    (unsigned char *)e + sizeof(struct arpt_entry) >= limit ||
	    (unsigned char *)e + e->next_offset > limit) {
		duprintf("Bad offset %p\n", e);
		return -EINVAL;
	}

	if (e->next_offset
	    < sizeof(struct arpt_entry) + sizeof(struct xt_entry_target)) {
		duprintf("checking: element %p size %u\n",
			 e, e->next_offset);
		return -EINVAL;
	}

	if (!arp_checkentry(&e->arp))
		return -EINVAL;

	err = xt_check_entry_offsets(e, e->target_offset, e->next_offset);
	if (err)
		return err;

	/* Check hooks & underflows */
	for (h = 0; h < NF_ARP_NUMHOOKS; h++) {
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
@@ -592,7 +592,8 @@
 	if (!arp_checkentry(&e->arp))
 		return -EINVAL;
 
-	err = xt_check_entry_offsets(e, e->target_offset, e->next_offset);
+	err = xt_check_entry_offsets(e, e->elems, e->target_offset,
+				     e->next_offset);
 	if (err)
 		return err;
 
@@ -1254,7 +1255,7 @@
 	if (!arp_checkentry(&e->arp))
 		return -EINVAL;
 
-	ret = xt_compat_check_entry_offsets(e, e->target_offset,
+	ret = xt_compat_check_entry_offsets(e, e->elems, e->target_offset,
 					    e->next_offset);
 	if (ret)
 		return ret;
```
