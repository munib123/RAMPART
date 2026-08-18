# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2557_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2557_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 64-104 of the vulnerable file.

{
	struct virtio_gpu_object *bo;
	enum ttm_bo_type type;
	size_t acc_size;
	int ret;

	if (kernel)
		type = ttm_bo_type_kernel;
	else
		type = ttm_bo_type_device;
	*bo_ptr = NULL;

	acc_size = ttm_bo_dma_acc_size(&vgdev->mman.bdev, size,
				       sizeof(struct virtio_gpu_object));

	bo = kzalloc(sizeof(struct virtio_gpu_object), GFP_KERNEL);
	if (bo == NULL)
		return -ENOMEM;
	size = roundup(size, PAGE_SIZE);
	ret = drm_gem_object_init(vgdev->ddev, &bo->gem_base, size);
	if (ret != 0)
		return ret;
	bo->dumb = false;
	virtio_gpu_init_ttm_placement(bo, pinned);

	ret = ttm_bo_init(&vgdev->mman.bdev, &bo->tbo, size, type,
			  &bo->placement, 0, !kernel, NULL, acc_size,
			  NULL, NULL, &virtio_gpu_ttm_bo_destroy);
	/* ttm_bo_init failure will call the destroy */
	if (ret != 0)
		return ret;

	*bo_ptr = bo;
	return 0;
}

int virtio_gpu_object_kmap(struct virtio_gpu_object *bo, void **ptr)
{
	bool is_iomem;
	int r;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,8 +81,10 @@
 		return -ENOMEM;
 	size = roundup(size, PAGE_SIZE);
 	ret = drm_gem_object_init(vgdev->ddev, &bo->gem_base, size);
-	if (ret != 0)
+	if (ret != 0) {
+		kfree(bo);
 		return ret;
+	}
 	bo->dumb = false;
 	virtio_gpu_init_ttm_placement(bo, pinned);
 
```
