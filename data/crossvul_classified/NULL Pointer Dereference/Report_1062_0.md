# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1062_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1062_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 24-64 of the vulnerable file.

MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);

/* single workqueue for entire fm10k driver */
struct workqueue_struct *fm10k_workqueue;

/**
 * fm10k_init_module - Driver Registration Routine
 *
 * fm10k_init_module is the first routine called when the driver is
 * loaded.  All it does is register with the PCI subsystem.
 **/
static int __init fm10k_init_module(void)
{
	pr_info("%s - version %s\n", fm10k_driver_string, fm10k_driver_version);
	pr_info("%s\n", fm10k_copyright);

	/* create driver workqueue */
	fm10k_workqueue = alloc_workqueue("%s", WQ_MEM_RECLAIM, 0,
					  fm10k_driver_name);

	fm10k_dbg_init();

	return fm10k_register_pci_driver();
}
module_init(fm10k_init_module);

/**
 * fm10k_exit_module - Driver Exit Cleanup Routine
 *
 * fm10k_exit_module is called just before the driver is removed
 * from memory.
 **/
static void __exit fm10k_exit_module(void)
{
	fm10k_unregister_pci_driver();

	fm10k_dbg_exit();

	/* destroy driver workqueue */
	destroy_workqueue(fm10k_workqueue);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,6 +41,8 @@
 	/* create driver workqueue */
 	fm10k_workqueue = alloc_workqueue("%s", WQ_MEM_RECLAIM, 0,
 					  fm10k_driver_name);
+	if (!fm10k_workqueue)
+		return -ENOMEM;
 
 	fm10k_dbg_init();
 
```
