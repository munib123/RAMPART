# CrossVul Fix Pair: Incorrect Default Permissions in c
**Pair ID:** 4225_1
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-276
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4225_1`)

## Vulnerability Information & PoC

## Description
Incorrect Default Permissions - During installation, installed file permissions are set to allow anyone to modify those files.

## Vulnerable Code
```c
Lines 285-325 of the vulnerable file.

#endif

static inline void write_ldt_entry(struct desc_struct *dt, int entry,
				   const void *desc)
{
	PVOP_VCALL3(cpu.write_ldt_entry, dt, entry, desc);
}

static inline void write_gdt_entry(struct desc_struct *dt, int entry,
				   void *desc, int type)
{
	PVOP_VCALL4(cpu.write_gdt_entry, dt, entry, desc, type);
}

static inline void write_idt_entry(gate_desc *dt, int entry, const gate_desc *g)
{
	PVOP_VCALL3(cpu.write_idt_entry, dt, entry, g);
}

#ifdef CONFIG_X86_IOPL_IOPERM
static inline void tss_update_io_bitmap(void)
{
	PVOP_VCALL0(cpu.update_io_bitmap);
}
#endif

static inline void paravirt_activate_mm(struct mm_struct *prev,
					struct mm_struct *next)
{
	PVOP_VCALL2(mmu.activate_mm, prev, next);
}

static inline void paravirt_arch_dup_mmap(struct mm_struct *oldmm,
					  struct mm_struct *mm)
{
	PVOP_VCALL2(mmu.dup_mmap, oldmm, mm);
}

static inline int paravirt_pgd_alloc(struct mm_struct *mm)
{
	return PVOP_CALL1(int, mmu.pgd_alloc, mm);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -302,6 +302,11 @@
 }
 
 #ifdef CONFIG_X86_IOPL_IOPERM
+static inline void tss_invalidate_io_bitmap(void)
+{
+	PVOP_VCALL0(cpu.invalidate_io_bitmap);
+}
+
 static inline void tss_update_io_bitmap(void)
 {
 	PVOP_VCALL0(cpu.update_io_bitmap);
```
