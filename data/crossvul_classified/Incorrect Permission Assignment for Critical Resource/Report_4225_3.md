# CrossVul Fix Pair: Incorrect Default Permissions in c
**Pair ID:** 4225_3
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-276
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4225_3`)

## Vulnerability Information & PoC

## Description
Incorrect Default Permissions - During installation, installed file permissions are set to allow anyone to modify those files.

## Vulnerable Code
```c
Lines 307-347 of the vulnerable file.

	.cpu.load_tls		= native_load_tls,
#ifdef CONFIG_X86_64
	.cpu.load_gs_index	= native_load_gs_index,
#endif
	.cpu.write_ldt_entry	= native_write_ldt_entry,
	.cpu.write_gdt_entry	= native_write_gdt_entry,
	.cpu.write_idt_entry	= native_write_idt_entry,

	.cpu.alloc_ldt		= paravirt_nop,
	.cpu.free_ldt		= paravirt_nop,

	.cpu.load_sp0		= native_load_sp0,

#ifdef CONFIG_X86_64
	.cpu.usergs_sysret64	= native_usergs_sysret64,
#endif
	.cpu.iret		= native_iret,
	.cpu.swapgs		= native_swapgs,

#ifdef CONFIG_X86_IOPL_IOPERM
	.cpu.update_io_bitmap	= native_tss_update_io_bitmap,
#endif

	.cpu.start_context_switch	= paravirt_nop,
	.cpu.end_context_switch		= paravirt_nop,

	/* Irq ops. */
	.irq.save_fl		= __PV_IS_CALLEE_SAVE(native_save_fl),
	.irq.restore_fl		= __PV_IS_CALLEE_SAVE(native_restore_fl),
	.irq.irq_disable	= __PV_IS_CALLEE_SAVE(native_irq_disable),
	.irq.irq_enable		= __PV_IS_CALLEE_SAVE(native_irq_enable),
	.irq.safe_halt		= native_safe_halt,
	.irq.halt		= native_halt,
#endif /* CONFIG_PARAVIRT_XXL */

	/* Mmu ops. */
	.mmu.flush_tlb_user	= native_flush_tlb_local,
	.mmu.flush_tlb_kernel	= native_flush_tlb_global,
	.mmu.flush_tlb_one_user	= native_flush_tlb_one_user,
	.mmu.flush_tlb_others	= native_flush_tlb_others,
	.mmu.tlb_remove_table	=
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -324,7 +324,8 @@
 	.cpu.swapgs		= native_swapgs,
 
 #ifdef CONFIG_X86_IOPL_IOPERM
-	.cpu.update_io_bitmap	= native_tss_update_io_bitmap,
+	.cpu.invalidate_io_bitmap	= native_tss_invalidate_io_bitmap,
+	.cpu.update_io_bitmap		= native_tss_update_io_bitmap,
 #endif
 
 	.cpu.start_context_switch	= paravirt_nop,
```
