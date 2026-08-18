# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5142_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5142_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 928-968 of the vulnerable file.


	switch (cmd) {
	case MIC_VIRTIO_ADD_DEVICE:
	{
		struct mic_device_desc dd, *dd_config;

		if (copy_from_user(&dd, argp, sizeof(dd)))
			return -EFAULT;

		if (mic_aligned_desc_size(&dd) > MIC_MAX_DESC_BLK_SIZE ||
		    dd.num_vq > MIC_MAX_VRINGS)
			return -EINVAL;

		dd_config = kzalloc(mic_desc_size(&dd), GFP_KERNEL);
		if (!dd_config)
			return -ENOMEM;
		if (copy_from_user(dd_config, argp, mic_desc_size(&dd))) {
			ret = -EFAULT;
			goto free_ret;
		}
		mutex_lock(&vdev->vdev_mutex);
		mutex_lock(&vi->vop_mutex);
		ret = vop_virtio_add_device(vdev, dd_config);
		if (ret)
			goto unlock_ret;
		list_add_tail(&vdev->list, &vi->vdev_list);
unlock_ret:
		mutex_unlock(&vi->vop_mutex);
		mutex_unlock(&vdev->vdev_mutex);
free_ret:
		kfree(dd_config);
		return ret;
	}
	case MIC_VIRTIO_COPY_DESC:
	{
		struct mic_copy_desc copy;

		mutex_lock(&vdev->vdev_mutex);
		ret = vop_vdev_inited(vdev);
		if (ret)
			goto _unlock_ret;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -945,6 +945,11 @@
 			ret = -EFAULT;
 			goto free_ret;
 		}
+		/* Ensure desc has not changed between the two reads */
+		if (memcmp(&dd, dd_config, sizeof(dd))) {
+			ret = -EINVAL;
+			goto free_ret;
+		}
 		mutex_lock(&vdev->vdev_mutex);
 		mutex_lock(&vi->vop_mutex);
 		ret = vop_virtio_add_device(vdev, dd_config);
```
