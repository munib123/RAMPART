# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 726_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `726_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 84-124 of the vulnerable file.

		return TEE_SUCCESS;
	}

	/* Belongs to nonsecure shared memory? */
	if (param_mem_from_mobj(mem, shm_mobj, pa, sz))
		return TEE_SUCCESS;

#ifdef CFG_SECURE_DATA_PATH
	/* Belongs to SDP memories? */
	for (mobj = sdp_mem_mobjs; *mobj; mobj++)
		if (param_mem_from_mobj(mem, *mobj, pa, sz))
			return TEE_SUCCESS;
#endif

	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result set_rmem_param(const struct optee_msg_param_rmem *rmem,
				 struct param_mem *mem)
{
	uint64_t shm_ref = READ_ONCE(rmem->shm_ref);

	mem->mobj = mobj_reg_shm_get_by_cookie(shm_ref);
	if (!mem->mobj)
		return TEE_ERROR_BAD_PARAMETERS;

	mem->offs = READ_ONCE(rmem->offs);
	mem->size = READ_ONCE(rmem->size);

	return TEE_SUCCESS;
}

static TEE_Result copy_in_params(const struct optee_msg_param *params,
				 uint32_t num_params,
				 struct tee_ta_param *ta_param,
				 uint64_t *saved_attr)
{
	TEE_Result res;
	size_t n;
	uint8_t pt[TEE_NUM_PARAMS] = { 0 };

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,6 +101,7 @@
 static TEE_Result set_rmem_param(const struct optee_msg_param_rmem *rmem,
 				 struct param_mem *mem)
 {
+	size_t req_size = 0;
 	uint64_t shm_ref = READ_ONCE(rmem->shm_ref);
 
 	mem->mobj = mobj_reg_shm_get_by_cookie(shm_ref);
@@ -109,6 +110,14 @@
 
 	mem->offs = READ_ONCE(rmem->offs);
 	mem->size = READ_ONCE(rmem->size);
+
+	/*
+	 * Check that the supplied offset and size is covered by the
+	 * previously verified MOBJ.
+	 */
+	if (ADD_OVERFLOW(mem->offs, mem->size, &req_size) ||
+	    mem->mobj->size < req_size)
+		return TEE_ERROR_SECURITY;
 
 	return TEE_SUCCESS;
 }
```
