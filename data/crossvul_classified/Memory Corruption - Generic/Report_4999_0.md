# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4999_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4999_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 342-382 of the vulnerable file.


		/* Target might have changed stuff. */
		arp = arp_hdr(skb);

		if (verdict == XT_CONTINUE)
			e = arpt_next_entry(e);
		else
			/* Verdict */
			break;
	} while (!acpar.hotdrop);
	xt_write_recseq_end(addend);
	local_bh_enable();

	if (acpar.hotdrop)
		return NF_DROP;
	else
		return verdict;
}

/* All zeroes == unconditional rule. */
static inline bool unconditional(const struct arpt_arp *arp)
{
	static const struct arpt_arp uncond;

	return memcmp(arp, &uncond, sizeof(uncond)) == 0;
}

/* Figures out from what hook each rule can be called: returns 0 if
 * there are loops.  Puts hook bitmask in comefrom.
 */
static int mark_source_chains(const struct xt_table_info *newinfo,
			      unsigned int valid_hooks, void *entry0)
{
	unsigned int hook;

	/* No recursion; use packet counter to save back ptrs (reset
	 * to 0 as we leave), and comefrom to save source hook bitmask.
	 */
	for (hook = 0; hook < NF_ARP_NUMHOOKS; hook++) {
		unsigned int pos = newinfo->hook_entry[hook];
		struct arpt_entry *e
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -359,11 +359,12 @@
 }
 
 /* All zeroes == unconditional rule. */
-static inline bool unconditional(const struct arpt_arp *arp)
+static inline bool unconditional(const struct arpt_entry *e)
 {
 	static const struct arpt_arp uncond;
 
-	return memcmp(arp, &uncond, sizeof(uncond)) == 0;
+	return e->target_offset == sizeof(struct arpt_entry) &&
+	       memcmp(&e->arp, &uncond, sizeof(uncond)) == 0;
 }
 
 /* Figures out from what hook each rule can be called: returns 0 if
@@ -402,11 +403,10 @@
 				|= ((1 << hook) | (1 << NF_ARP_NUMHOOKS));
 
 			/* Unconditional return/END. */
-			if ((e->target_offset == sizeof(struct arpt_entry) &&
+			if ((unconditional(e) &&
 			     (strcmp(t->target.u.user.name,
 				     XT_STANDARD_TARGET) == 0) &&
-			     t->verdict < 0 && unconditional(&e->arp)) ||
-			    visited) {
+			     t->verdict < 0) || visited) {
 				unsigned int oldpos, size;
 
 				if ((strcmp(t->target.u.user.name,
@@ -551,7 +551,7 @@
 	const struct xt_entry_target *t;
 	unsigned int verdict;
 
-	if (!unconditional(&e->arp))
+	if (!unconditional(e))
 		return false;
 	t = arpt_get_target_c(e);
 	if (strcmp(t->u.user.name, XT_STANDARD_TARGET) != 0)
@@ -598,9 +598,9 @@
 			newinfo->hook_entry[h] = hook_entries[h];
 		if ((unsigned char *)e - base == underflows[h]) {
 			if (!check_underflow(e)) {
-				pr_err("Underflows must be unconditional and "
-				       "use the STANDARD target with "
-				       "ACCEPT/DROP\n");
+				pr_debug("Underflows must be unconditional and "
+					 "use the STANDARD target with "
+					 "ACCEPT/DROP\n");
 				return -EINVAL;
 			}
 			newinfo->underflow[h] = underflows[h];
```
