# CrossVul Fix Pair: Incorrect Default Permissions in c
**Pair ID:** 4225_2
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-276
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4225_2`)

## Vulnerability Information & PoC

## Description
Incorrect Default Permissions - During installation, installed file permissions are set to allow anyone to modify those files.

## Vulnerable Code
```c
Lines 124-164 of the vulnerable file.

	void (*load_gdt)(const struct desc_ptr *);
	void (*load_idt)(const struct desc_ptr *);
	void (*set_ldt)(const void *desc, unsigned entries);
	unsigned long (*store_tr)(void);
	void (*load_tls)(struct thread_struct *t, unsigned int cpu);
#ifdef CONFIG_X86_64
	void (*load_gs_index)(unsigned int idx);
#endif
	void (*write_ldt_entry)(struct desc_struct *ldt, int entrynum,
				const void *desc);
	void (*write_gdt_entry)(struct desc_struct *,
				int entrynum, const void *desc, int size);
	void (*write_idt_entry)(gate_desc *,
				int entrynum, const gate_desc *gate);
	void (*alloc_ldt)(struct desc_struct *ldt, unsigned entries);
	void (*free_ldt)(struct desc_struct *ldt, unsigned entries);

	void (*load_sp0)(unsigned long sp0);

#ifdef CONFIG_X86_IOPL_IOPERM
	void (*update_io_bitmap)(void);
#endif

	void (*wbinvd)(void);

	/* cpuid emulation, mostly so that caps bits can be disabled */
	void (*cpuid)(unsigned int *eax, unsigned int *ebx,
		      unsigned int *ecx, unsigned int *edx);

	/* Unsafe MSR operations.  These will warn or panic on failure. */
	u64 (*read_msr)(unsigned int msr);
	void (*write_msr)(unsigned int msr, unsigned low, unsigned high);

	/*
	 * Safe MSR operations.
	 * read sets err to 0 or -EIO.  write returns 0 or -EIO.
	 */
	u64 (*read_msr_safe)(unsigned int msr, int *err);
	int (*write_msr_safe)(unsigned int msr, unsigned low, unsigned high);

	u64 (*read_pmc)(int counter);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -141,6 +141,7 @@
 	void (*load_sp0)(unsigned long sp0);
 
 #ifdef CONFIG_X86_IOPL_IOPERM
+	void (*invalidate_io_bitmap)(void);
 	void (*update_io_bitmap)(void);
 #endif
 
```
