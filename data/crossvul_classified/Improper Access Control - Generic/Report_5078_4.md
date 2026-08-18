# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5078_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5078_4`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 529-570 of the vulnerable file.

	if (match->compat_to_user) {
		if (match->compat_to_user((void __user *)cm->data, m->data))
			return -EFAULT;
	} else {
		if (copy_to_user(cm->data, m->data, msize - sizeof(*cm)))
			return -EFAULT;
	}

	*size -= off;
	*dstptr += msize;
	return 0;
}
EXPORT_SYMBOL_GPL(xt_compat_match_to_user);

/* non-compat version may have padding after verdict */
struct compat_xt_standard_target {
	struct compat_xt_entry_target t;
	compat_uint_t verdict;
};

/* see xt_check_entry_offsets */
int xt_compat_check_entry_offsets(const void *base,
				  unsigned int target_offset,
				  unsigned int next_offset)
{
	const struct compat_xt_entry_target *t;
	const char *e = base;

	if (target_offset + sizeof(*t) > next_offset)
		return -EINVAL;

	t = (void *)(e + target_offset);
	if (t->u.target_size < sizeof(*t))
		return -EINVAL;

	if (target_offset + t->u.target_size > next_offset)
		return -EINVAL;

	if (strcmp(t->u.user.name, XT_STANDARD_TARGET) == 0 &&
	    target_offset + sizeof(struct compat_xt_standard_target) != next_offset)
		return -EINVAL;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -546,13 +546,16 @@
 	compat_uint_t verdict;
 };
 
-/* see xt_check_entry_offsets */
-int xt_compat_check_entry_offsets(const void *base,
+int xt_compat_check_entry_offsets(const void *base, const char *elems,
 				  unsigned int target_offset,
 				  unsigned int next_offset)
 {
+	long size_of_base_struct = elems - (const char *)base;
 	const struct compat_xt_entry_target *t;
 	const char *e = base;
+
+	if (target_offset < size_of_base_struct)
+		return -EINVAL;
 
 	if (target_offset + sizeof(*t) > next_offset)
 		return -EINVAL;
@@ -577,11 +580,15 @@
  * xt_check_entry_offsets - validate arp/ip/ip6t_entry
  *
  * @base: pointer to arp/ip/ip6t_entry
+ * @elems: pointer to first xt_entry_match, i.e. ip(6)t_entry->elems
  * @target_offset: the arp/ip/ip6_t->target_offset
  * @next_offset: the arp/ip/ip6_t->next_offset
  *
  * validates that target_offset and next_offset are sane.
  * Also see xt_compat_check_entry_offsets for CONFIG_COMPAT version.
+ *
+ * This function does not validate the targets or matches themselves, it
+ * only tests that all the offsets and sizes are correct.
  *
  * The arp/ip/ip6t_entry structure @base must have passed following tests:
  * - it must point to a valid memory location
@@ -591,11 +598,17 @@
  * Return: 0 on success, negative errno on failure.
  */
 int xt_check_entry_offsets(const void *base,
+			   const char *elems,
 			   unsigned int target_offset,
 			   unsigned int next_offset)
 {
+	long size_of_base_struct = elems - (const char *)base;
 	const struct xt_entry_target *t;
 	const char *e = base;
+
+	/* target start is within the ip/ip6/arpt_entry struct */
+	if (target_offset < size_of_base_struct)
+		return -EINVAL;
 
 	if (target_offset + sizeof(*t) > next_offset)
 		return -EINVAL;
```
