# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3535_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3535_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1-40 of the vulnerable file.

/*
 * Kernel-based Virtual Machine - device assignment support
 *
 * Copyright (C) 2010 Red Hat, Inc. and/or its affiliates.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include "irq.h"

static struct kvm_assigned_dev_kernel *kvm_find_assigned_dev(struct list_head *head,
						      int assigned_dev_id)
{
	struct list_head *ptr;
	struct kvm_assigned_dev_kernel *match;

	list_for_each(ptr, head) {
		match = list_entry(ptr, struct kvm_assigned_dev_kernel, list);
		if (match->assigned_dev_id == assigned_dev_id)
			return match;
	}
	return NULL;
}

static int find_index_from_host_irq(struct kvm_assigned_dev_kernel
				    *assigned_dev, int irq)
{
	int i, index;
	struct msix_entry *host_msix_entries;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,8 @@
 #include <linux/pci.h>
 #include <linux/interrupt.h>
 #include <linux/slab.h>
+#include <linux/namei.h>
+#include <linux/fs.h>
 #include "irq.h"
 
 static struct kvm_assigned_dev_kernel *kvm_find_assigned_dev(struct list_head *head,
@@ -474,12 +476,73 @@
 	return r;
 }
 
+/*
+ * We want to test whether the caller has been granted permissions to
+ * use this device.  To be able to configure and control the device,
+ * the user needs access to PCI configuration space and BAR resources.
+ * These are accessed through PCI sysfs.  PCI config space is often
+ * passed to the process calling this ioctl via file descriptor, so we
+ * can't rely on access to that file.  We can check for permissions
+ * on each of the BAR resource files, which is a pretty clear
+ * indicator that the user has been granted access to the device.
+ */
+static int probe_sysfs_permissions(struct pci_dev *dev)
+{
+#ifdef CONFIG_SYSFS
+	int i;
+	bool bar_found = false;
+
+	for (i = PCI_STD_RESOURCES; i <= PCI_STD_RESOURCE_END; i++) {
+		char *kpath, *syspath;
+		struct path path;
+		struct inode *inode;
+		int r;
+
+		if (!pci_resource_len(dev, i))
+			continue;
+
+		kpath = kobject_get_path(&dev->dev.kobj, GFP_KERNEL);
+		if (!kpath)
+			return -ENOMEM;
+
+		/* Per sysfs-rules, sysfs is always at /sys */
+		syspath = kasprintf(GFP_KERNEL, "/sys%s/resource%d", kpath, i);
+		kfree(kpath);
+		if (!syspath)
+			return -ENOMEM;
+
+		r = kern_path(syspath, LOOKUP_FOLLOW, &path);
+		kfree(syspath);
+		if (r)
+			return r;
+
+		inode = path.dentry->d_inode;
+
+		r = inode_permission(inode, MAY_READ | MAY_WRITE | MAY_ACCESS);
+		path_put(&path);
+		if (r)
+			return r;
+
+		bar_found = true;
+	}
+
+	/* If no resources, probably something special */
+	if (!bar_found)
+		return -EPERM;
+
+	return 0;
+#else
+	return -EINVAL; /* No way to control the device without sysfs */
+#endif
+}
+
 static int kvm_vm_ioctl_assign_device(struct kvm *kvm,
 				      struct kvm_assigned_pci_dev *assigned_dev)
 {
 	int r = 0, idx;
 	struct kvm_assigned_dev_kernel *match;
 	struct pci_dev *dev;
+	u8 header_type;
 
 	if (!(assigned_dev->flags & KVM_DEV_ASSIGN_ENABLE_IOMMU))
 		return -EINVAL;
@@ -510,6 +573,18 @@
 		r = -EINVAL;
 		goto out_free;
 	}
+
+	/* Don't allow bridges to be assigned */
+	pci_read_config_byte(dev, PCI_HEADER_TYPE, &header_type);
+	if ((header_type & PCI_HEADER_TYPE) != PCI_HEADER_TYPE_NORMAL) {
+		r = -EPERM;
+		goto out_put;
+	}
+
+	r = probe_sysfs_permissions(dev);
+	if (r)
+		goto out_put;
+
 	if (pci_enable_device(dev)) {
 		printk(KERN_INFO "%s: Could not enable PCI device\n", __func__);
 		r = -EBUSY;
```
