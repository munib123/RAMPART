# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 731_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `731_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1742-1782 of the vulnerable file.

	if ((o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0)
		return TEE_ERROR_BAD_STATE;

	/* Must not be initialized already */
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != 0)
		return TEE_ERROR_BAD_STATE;

	/* Find description of object */
	type_props = tee_svc_find_type_props(o->info.objectType);
	if (!type_props)
		return TEE_ERROR_NOT_SUPPORTED;

	/* Check that maxKeySize follows restrictions */
	if (key_size % type_props->quanta != 0)
		return TEE_ERROR_NOT_SUPPORTED;
	if (key_size < type_props->min_size)
		return TEE_ERROR_NOT_SUPPORTED;
	if (key_size > type_props->max_size)
		return TEE_ERROR_NOT_SUPPORTED;

	params = malloc(sizeof(TEE_Attribute) * param_count);
	if (!params)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = copy_in_attrs(to_user_ta_ctx(sess->ctx), usr_params, param_count,
			    params);
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_svc_cryp_check_attr(ATTR_USAGE_GENERATE_KEY, type_props,
				      params, param_count);
	if (res != TEE_SUCCESS)
		goto out;

	switch (o->info.objectType) {
	case TEE_TYPE_AES:
	case TEE_TYPE_DES:
	case TEE_TYPE_DES3:
	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1759,7 +1759,12 @@
 	if (key_size > type_props->max_size)
 		return TEE_ERROR_NOT_SUPPORTED;
 
-	params = malloc(sizeof(TEE_Attribute) * param_count);
+	size_t alloc_size = 0;
+
+	if (MUL_OVERFLOW(sizeof(TEE_Attribute), param_count, &alloc_size))
+		return TEE_ERROR_OVERFLOW;
+
+	params = malloc(alloc_size);
 	if (!params)
 		return TEE_ERROR_OUT_OF_MEMORY;
 	res = copy_in_attrs(to_user_ta_ctx(sess->ctx), usr_params, param_count,
@@ -2668,7 +2673,12 @@
 	if (res != TEE_SUCCESS)
 		return res;
 
-	params = malloc(sizeof(TEE_Attribute) * param_count);
+	size_t alloc_size = 0;
+
+	if (MUL_OVERFLOW(sizeof(TEE_Attribute), param_count, &alloc_size))
+		return TEE_ERROR_OVERFLOW;
+
+	params = malloc(alloc_size);
 	if (!params)
 		return TEE_ERROR_OUT_OF_MEMORY;
 	res = copy_in_attrs(utc, usr_params, param_count, params);
```
