# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3401_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3401_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1257-1297 of the vulnerable file.

 *
 * @dev:            Pointer to a struct drm_device.
 * @data:           Pointer to data copied from / to user-space.
 * @file_priv:      Pointer to a drm file private structure.
 */
int vmw_gb_surface_define_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file_priv)
{
	struct vmw_private *dev_priv = vmw_priv(dev);
	struct vmw_user_surface *user_srf;
	struct vmw_surface *srf;
	struct vmw_resource *res;
	struct vmw_resource *tmp;
	union drm_vmw_gb_surface_create_arg *arg =
	    (union drm_vmw_gb_surface_create_arg *)data;
	struct drm_vmw_gb_surface_create_req *req = &arg->req;
	struct drm_vmw_gb_surface_create_rep *rep = &arg->rep;
	struct ttm_object_file *tfile = vmw_fpriv(file_priv)->tfile;
	int ret;
	uint32_t size;
	uint32_t backup_handle;

	if (req->multisample_count != 0)
		return -EINVAL;

	if (req->mip_levels > DRM_VMW_MAX_MIP_LEVELS)
		return -EINVAL;

	if (unlikely(vmw_user_surface_size == 0))
		vmw_user_surface_size = ttm_round_pot(sizeof(*user_srf)) +
			128;

	size = vmw_user_surface_size + 128;

	/* Define a surface based on the parameters. */
	ret = vmw_surface_gb_priv_define(dev,
			size,
			req->svga3d_flags,
			req->format,
			req->drm_surface_flags & drm_vmw_surface_flag_scanout,
			req->mip_levels,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1274,7 +1274,7 @@
 	struct ttm_object_file *tfile = vmw_fpriv(file_priv)->tfile;
 	int ret;
 	uint32_t size;
-	uint32_t backup_handle;
+	uint32_t backup_handle = 0;
 
 	if (req->multisample_count != 0)
 		return -EINVAL;
@@ -1317,12 +1317,16 @@
 		ret = vmw_user_dmabuf_lookup(tfile, req->buffer_handle,
 					     &res->backup,
 					     &user_srf->backup_base);
-		if (ret == 0 && res->backup->base.num_pages * PAGE_SIZE <
-		    res->backup_size) {
-			DRM_ERROR("Surface backup buffer is too small.\n");
-			vmw_dmabuf_unreference(&res->backup);
-			ret = -EINVAL;
-			goto out_unlock;
+		if (ret == 0) {
+			if (res->backup->base.num_pages * PAGE_SIZE <
+			    res->backup_size) {
+				DRM_ERROR("Surface backup buffer is too small.\n");
+				vmw_dmabuf_unreference(&res->backup);
+				ret = -EINVAL;
+				goto out_unlock;
+			} else {
+				backup_handle = req->buffer_handle;
+			}
 		}
 	} else if (req->drm_surface_flags & drm_vmw_surface_flag_create_buffer)
 		ret = vmw_user_dmabuf_alloc(dev_priv, tfile,
```
