# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5375_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5375_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 812-852 of the vulnerable file.

		/* pass thru to return error */
		default:
			return -EINVAL;
		}

		info.flags = VFIO_IRQ_INFO_EVENTFD;

		info.count = vfio_pci_get_irq_count(vdev, info.index);

		if (info.index == VFIO_PCI_INTX_IRQ_INDEX)
			info.flags |= (VFIO_IRQ_INFO_MASKABLE |
				       VFIO_IRQ_INFO_AUTOMASKED);
		else
			info.flags |= VFIO_IRQ_INFO_NORESIZE;

		return copy_to_user((void __user *)arg, &info, minsz) ?
			-EFAULT : 0;

	} else if (cmd == VFIO_DEVICE_SET_IRQS) {
		struct vfio_irq_set hdr;
		u8 *data = NULL;
		int ret = 0;

		minsz = offsetofend(struct vfio_irq_set, count);

		if (copy_from_user(&hdr, (void __user *)arg, minsz))
			return -EFAULT;

		if (hdr.argsz < minsz || hdr.index >= VFIO_PCI_NUM_IRQS ||
		    hdr.flags & ~(VFIO_IRQ_SET_DATA_TYPE_MASK |
				  VFIO_IRQ_SET_ACTION_TYPE_MASK))
			return -EINVAL;

		if (!(hdr.flags & VFIO_IRQ_SET_DATA_NONE)) {
			size_t size;
			int max = vfio_pci_get_irq_count(vdev, hdr.index);

			if (hdr.flags & VFIO_IRQ_SET_DATA_BOOL)
				size = sizeof(uint8_t);
			else if (hdr.flags & VFIO_IRQ_SET_DATA_EVENTFD)
				size = sizeof(int32_t);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -829,8 +829,9 @@
 
 	} else if (cmd == VFIO_DEVICE_SET_IRQS) {
 		struct vfio_irq_set hdr;
+		size_t size;
 		u8 *data = NULL;
-		int ret = 0;
+		int max, ret = 0;
 
 		minsz = offsetofend(struct vfio_irq_set, count);
 
@@ -838,23 +839,31 @@
 			return -EFAULT;
 
 		if (hdr.argsz < minsz || hdr.index >= VFIO_PCI_NUM_IRQS ||
+		    hdr.count >= (U32_MAX - hdr.start) ||
 		    hdr.flags & ~(VFIO_IRQ_SET_DATA_TYPE_MASK |
 				  VFIO_IRQ_SET_ACTION_TYPE_MASK))
 			return -EINVAL;
 
-		if (!(hdr.flags & VFIO_IRQ_SET_DATA_NONE)) {
-			size_t size;
-			int max = vfio_pci_get_irq_count(vdev, hdr.index);
-
-			if (hdr.flags & VFIO_IRQ_SET_DATA_BOOL)
-				size = sizeof(uint8_t);
-			else if (hdr.flags & VFIO_IRQ_SET_DATA_EVENTFD)
-				size = sizeof(int32_t);
-			else
-				return -EINVAL;
-
-			if (hdr.argsz - minsz < hdr.count * size ||
-			    hdr.start >= max || hdr.start + hdr.count > max)
+		max = vfio_pci_get_irq_count(vdev, hdr.index);
+		if (hdr.start >= max || hdr.start + hdr.count > max)
+			return -EINVAL;
+
+		switch (hdr.flags & VFIO_IRQ_SET_DATA_TYPE_MASK) {
+		case VFIO_IRQ_SET_DATA_NONE:
+			size = 0;
+			break;
+		case VFIO_IRQ_SET_DATA_BOOL:
+			size = sizeof(uint8_t);
+			break;
+		case VFIO_IRQ_SET_DATA_EVENTFD:
+			size = sizeof(int32_t);
+			break;
+		default:
+			return -EINVAL;
+		}
+
+		if (size) {
+			if (hdr.argsz - minsz < hdr.count * size)
 				return -EINVAL;
 
 			data = memdup_user((void __user *)(arg + minsz),
```
