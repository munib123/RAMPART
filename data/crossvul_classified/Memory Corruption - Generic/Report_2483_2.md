# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2483_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2483_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 98-138 of the vulnerable file.

 * bundles to load the physical address.
 */
void __init
ia64_patch_vtop (unsigned long start, unsigned long end)
{
	s32 *offp = (s32 *) start;
	u64 ip;

	while (offp < (s32 *) end) {
		ip = (u64) offp + *offp;

		/* replace virtual address with corresponding physical address: */
		ia64_patch_imm64(ip, ia64_tpa(get_imm64(ip)));
		ia64_fc((void *) ip);
		++offp;
	}
	ia64_sync_i();
	ia64_srlz_i();
}

void __init
ia64_patch_mckinley_e9 (unsigned long start, unsigned long end)
{
	static int first_time = 1;
	int need_workaround;
	s32 *offp = (s32 *) start;
	u64 *wp;

	need_workaround = (local_cpu_data->family == 0x1f && local_cpu_data->model == 0);

	if (first_time) {
		first_time = 0;
		if (need_workaround)
			printk(KERN_INFO "Leaving McKinley Errata 9 workaround enabled\n");
	}
	if (need_workaround)
		return;

	while (offp < (s32 *) end) {
		wp = (u64 *) ia64_imva((char *) offp + *offp);
		wp[0] = 0x0000000100000011UL; /* nop.m 0; nop.i 0; br.ret.sptk.many b6 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -115,6 +115,29 @@
 	ia64_srlz_i();
 }
 
+/*
+ * Disable the RSE workaround by turning the conditional branch
+ * that we tagged in each place the workaround was used into an
+ * unconditional branch.
+ */
+void __init
+ia64_patch_rse (unsigned long start, unsigned long end)
+{
+	s32 *offp = (s32 *) start;
+	u64 ip, *b;
+
+	while (offp < (s32 *) end) {
+		ip = (u64) offp + *offp;
+
+		b = (u64 *)(ip & -16);
+		b[1] &= ~0xf800000L;
+		ia64_fc((void *) ip);
+		++offp;
+	}
+	ia64_sync_i();
+	ia64_srlz_i();
+}
+
 void __init
 ia64_patch_mckinley_e9 (unsigned long start, unsigned long end)
 {
```
