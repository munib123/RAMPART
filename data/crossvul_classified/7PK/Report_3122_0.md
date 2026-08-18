# CrossVul Fix Pair: 7PK in c
**Pair ID:** 3122_0
**Vulnerability Class:** 7PK
**CWE:** CWE-388
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3122_0`)

## Vulnerability Information & PoC

## Description
7PK - Errors

## Vulnerable Code
```c
Lines 584-624 of the vulnerable file.

	struct drm_vc4_submit_cl *args = exec->args;
	void *temp = NULL;
	void *bin;
	int ret = 0;
	uint32_t bin_offset = 0;
	uint32_t shader_rec_offset = roundup(bin_offset + args->bin_cl_size,
					     16);
	uint32_t uniforms_offset = shader_rec_offset + args->shader_rec_size;
	uint32_t exec_size = uniforms_offset + args->uniforms_size;
	uint32_t temp_size = exec_size + (sizeof(struct vc4_shader_state) *
					  args->shader_rec_count);
	struct vc4_bo *bo;

	if (shader_rec_offset < args->bin_cl_size ||
	    uniforms_offset < shader_rec_offset ||
	    exec_size < uniforms_offset ||
	    args->shader_rec_count >= (UINT_MAX /
					  sizeof(struct vc4_shader_state)) ||
	    temp_size < exec_size) {
		DRM_ERROR("overflow in exec arguments\n");
		goto fail;
	}

	/* Allocate space where we'll store the copied in user command lists
	 * and shader records.
	 *
	 * We don't just copy directly into the BOs because we need to
	 * read the contents back for validation, and I think the
	 * bo->vaddr is uncached access.
	 */
	temp = drm_malloc_ab(temp_size, 1);
	if (!temp) {
		DRM_ERROR("Failed to allocate storage for copying "
			  "in bin/render CLs.\n");
		ret = -ENOMEM;
		goto fail;
	}
	bin = temp + bin_offset;
	exec->shader_rec_u = temp + shader_rec_offset;
	exec->uniforms_u = temp + uniforms_offset;
	exec->shader_state = temp + exec_size;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -601,6 +601,7 @@
 					  sizeof(struct vc4_shader_state)) ||
 	    temp_size < exec_size) {
 		DRM_ERROR("overflow in exec arguments\n");
+		ret = -EINVAL;
 		goto fail;
 	}
 
```
