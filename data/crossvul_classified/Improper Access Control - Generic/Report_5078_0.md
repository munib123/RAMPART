# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5078_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5078_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 225-265 of the vulnerable file.

	/*
	 * Number of user chains. Since tables cannot have loops, at most
	 * @stacksize jumps (number of user chains) can possibly be made.
	 */
	unsigned int stacksize;
	void ***jumpstack;

	unsigned char entries[0] __aligned(8);
};

int xt_register_target(struct xt_target *target);
void xt_unregister_target(struct xt_target *target);
int xt_register_targets(struct xt_target *target, unsigned int n);
void xt_unregister_targets(struct xt_target *target, unsigned int n);

int xt_register_match(struct xt_match *target);
void xt_unregister_match(struct xt_match *target);
int xt_register_matches(struct xt_match *match, unsigned int n);
void xt_unregister_matches(struct xt_match *match, unsigned int n);

int xt_check_entry_offsets(const void *base,
			   unsigned int target_offset,
			   unsigned int next_offset);

int xt_check_match(struct xt_mtchk_param *, unsigned int size, u_int8_t proto,
		   bool inv_proto);
int xt_check_target(struct xt_tgchk_param *, unsigned int size, u_int8_t proto,
		    bool inv_proto);

struct xt_table *xt_register_table(struct net *net,
				   const struct xt_table *table,
				   struct xt_table_info *bootstrap,
				   struct xt_table_info *newinfo);
void *xt_unregister_table(struct xt_table *table);

struct xt_table_info *xt_replace_table(struct xt_table *table,
				       unsigned int num_counters,
				       struct xt_table_info *newinfo,
				       int *error);

struct xt_match *xt_find_match(u8 af, const char *name, u8 revision);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -242,7 +242,7 @@
 int xt_register_matches(struct xt_match *match, unsigned int n);
 void xt_unregister_matches(struct xt_match *match, unsigned int n);
 
-int xt_check_entry_offsets(const void *base,
+int xt_check_entry_offsets(const void *base, const char *elems,
 			   unsigned int target_offset,
 			   unsigned int next_offset);
 
@@ -494,7 +494,7 @@
 				unsigned int *size);
 int xt_compat_target_to_user(const struct xt_entry_target *t,
 			     void __user **dstptr, unsigned int *size);
-int xt_compat_check_entry_offsets(const void *base,
+int xt_compat_check_entry_offsets(const void *base, const char *elems,
 				  unsigned int target_offset,
 				  unsigned int next_offset);
 
```
