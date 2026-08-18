# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 729_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `729_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 477-517 of the vulnerable file.


	res = TEE_ERROR_ITEM_NOT_FOUND;
	for (i = 0; i < size; i++) {
		if (!strcmp(kname, props[i].name)) {
			res = tee_svc_copy_to_user(index, &i, sizeof(*index));
			goto out;
		}
	}
	for (i = size; i < size + vendor_size; i++) {
		if (!strcmp(kname, vendor_props[i - size].name)) {
			res = tee_svc_copy_to_user(index, &i, sizeof(*index));
			goto out;
		}
	}

out:
	free(kname);
	return res;
}

static void utee_param_to_param(struct tee_ta_param *p, struct utee_params *up)
{
	size_t n;
	uint32_t types = up->types;

	p->types = types;
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uintptr_t a = up->vals[n * 2];
		size_t b = up->vals[n * 2 + 1];

		switch (TEE_PARAM_TYPE_GET(types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			p->u[n].mem.mobj = &mobj_virt;
			p->u[n].mem.offs = a;
			p->u[n].mem.size = b;
			break;
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			p->u[n].val.a = a;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -494,7 +494,9 @@
 	return res;
 }
 
-static void utee_param_to_param(struct tee_ta_param *p, struct utee_params *up)
+static TEE_Result utee_param_to_param(struct user_ta_ctx *utc,
+				      struct tee_ta_param *p,
+				      struct utee_params *up)
 {
 	size_t n;
 	uint32_t types = up->types;
@@ -503,14 +505,20 @@
 	for (n = 0; n < TEE_NUM_PARAMS; n++) {
 		uintptr_t a = up->vals[n * 2];
 		size_t b = up->vals[n * 2 + 1];
+		uint32_t flags = TEE_MEMORY_ACCESS_READ |
+				 TEE_MEMORY_ACCESS_ANY_OWNER;
 
 		switch (TEE_PARAM_TYPE_GET(types, n)) {
-		case TEE_PARAM_TYPE_MEMREF_INPUT:
 		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
 		case TEE_PARAM_TYPE_MEMREF_INOUT:
+			flags |= TEE_MEMORY_ACCESS_WRITE;
+			/*FALLTHROUGH*/
+		case TEE_PARAM_TYPE_MEMREF_INPUT:
 			p->u[n].mem.mobj = &mobj_virt;
 			p->u[n].mem.offs = a;
 			p->u[n].mem.size = b;
+			if (tee_mmu_check_access_rights(utc, flags, a, b))
+				return TEE_ERROR_ACCESS_DENIED;
 			break;
 		case TEE_PARAM_TYPE_VALUE_INPUT:
 		case TEE_PARAM_TYPE_VALUE_INOUT:
@@ -522,6 +530,8 @@
 			break;
 		}
 	}
+
+	return TEE_SUCCESS;
 }
 
 static TEE_Result alloc_temp_sec_mem(size_t size, struct mobj **mobj,
@@ -575,7 +585,9 @@
 			(uaddr_t)callee_params, sizeof(struct utee_params));
 		if (res != TEE_SUCCESS)
 			return res;
-		utee_param_to_param(param, callee_params);
+		res = utee_param_to_param(utc, param, callee_params);
+		if (res != TEE_SUCCESS)
+			return res;
 	}
 
 	if (called_sess && is_pseudo_ta_ctx(called_sess->ctx)) {
```
