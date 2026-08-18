# CrossVul Fix Pair: Incorrect Default Permissions in c
**Pair ID:** 4225_5
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-276
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4225_5`)

## Vulnerability Information & PoC

## Description
Incorrect Default Permissions - During installation, installed file permissions are set to allow anyone to modify those files.

## Vulnerable Code
```c
Lines 853-893 of the vulnerable file.

		xmaddr_t maddr = virt_to_machine(&dt[entry]);

		if (HYPERVISOR_update_descriptor(maddr.maddr, *(u64 *)desc))
			dt[entry] = *(struct desc_struct *)desc;
	}

	}
}

static void xen_load_sp0(unsigned long sp0)
{
	struct multicall_space mcs;

	mcs = xen_mc_entry(0);
	MULTI_stack_switch(mcs.mc, __KERNEL_DS, sp0);
	xen_mc_issue(PARAVIRT_LAZY_CPU);
	this_cpu_write(cpu_tss_rw.x86_tss.sp0, sp0);
}

#ifdef CONFIG_X86_IOPL_IOPERM
static void xen_update_io_bitmap(void)
{
	struct physdev_set_iobitmap iobitmap;
	struct tss_struct *tss = this_cpu_ptr(&cpu_tss_rw);

	native_tss_update_io_bitmap();

	iobitmap.bitmap = (uint8_t *)(&tss->x86_tss) +
			  tss->x86_tss.io_bitmap_base;
	if (tss->x86_tss.io_bitmap_base == IO_BITMAP_OFFSET_INVALID)
		iobitmap.nr_ports = 0;
	else
		iobitmap.nr_ports = IO_BITMAP_BITS;

	HYPERVISOR_physdev_op(PHYSDEVOP_set_iobitmap, &iobitmap);
}
#endif

static void xen_io_delay(void)
{
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -870,6 +870,17 @@
 }
 
 #ifdef CONFIG_X86_IOPL_IOPERM
+static void xen_invalidate_io_bitmap(void)
+{
+	struct physdev_set_iobitmap iobitmap = {
+		.bitmap = 0,
+		.nr_ports = 0,
+	};
+
+	native_tss_invalidate_io_bitmap();
+	HYPERVISOR_physdev_op(PHYSDEVOP_set_iobitmap, &iobitmap);
+}
+
 static void xen_update_io_bitmap(void)
 {
 	struct physdev_set_iobitmap iobitmap;
@@ -1099,6 +1110,7 @@
 	.load_sp0 = xen_load_sp0,
 
 #ifdef CONFIG_X86_IOPL_IOPERM
+	.invalidate_io_bitmap = xen_invalidate_io_bitmap,
 	.update_io_bitmap = xen_update_io_bitmap,
 #endif
 	.io_delay = xen_io_delay,
```
