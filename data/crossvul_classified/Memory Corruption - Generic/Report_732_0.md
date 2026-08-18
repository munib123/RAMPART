# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 732_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `732_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 3257-3297 of the vulnerable file.

	res = tee_mmu_check_access_rights(
		utc,
		TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER,
		(uaddr_t) src_data, src_len);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_copy_from_user(&dlen64, dst_len, sizeof(dlen64));
	if (res != TEE_SUCCESS)
		return res;
	dlen = dlen64;

	res = tee_mmu_check_access_rights(
		utc,
		TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE |
			TEE_MEMORY_ACCESS_ANY_OWNER,
		(uaddr_t) dst_data, dlen);
	if (res != TEE_SUCCESS)
		return res;

	params = malloc(sizeof(TEE_Attribute) * num_params);
	if (!params)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = copy_in_attrs(utc, usr_params, num_params, params);
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_obj_get(utc, cs->key1, &o);
	if (res != TEE_SUCCESS)
		goto out;
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	switch (cs->algo) {
	case TEE_ALG_RSA_NOPAD:
		if (cs->mode == TEE_MODE_ENCRYPT) {
			res = crypto_acipher_rsanopad_encrypt(o->attr, src_data,
							      src_len, dst_data,
							      &dlen);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3274,7 +3274,12 @@
 	if (res != TEE_SUCCESS)
 		return res;
 
-	params = malloc(sizeof(TEE_Attribute) * num_params);
+	size_t alloc_size = 0;
+
+	if (MUL_OVERFLOW(sizeof(TEE_Attribute), num_params, &alloc_size))
+		return TEE_ERROR_OVERFLOW;
+
+	params = malloc(alloc_size);
 	if (!params)
 		return TEE_ERROR_OUT_OF_MEMORY;
 	res = copy_in_attrs(utc, usr_params, num_params, params);
@@ -3436,7 +3441,12 @@
 	if (res != TEE_SUCCESS)
 		return res;
 
-	params = malloc(sizeof(TEE_Attribute) * num_params);
+	size_t alloc_size = 0;
+
+	if (MUL_OVERFLOW(sizeof(TEE_Attribute), num_params, &alloc_size))
+		return TEE_ERROR_OVERFLOW;
+
+	params = malloc(alloc_size);
 	if (!params)
 		return TEE_ERROR_OUT_OF_MEMORY;
 	res = copy_in_attrs(utc, usr_params, num_params, params);
```
