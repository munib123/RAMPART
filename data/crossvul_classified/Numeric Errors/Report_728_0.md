# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 728_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `728_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 180-221 of the vulnerable file.

			memcpy(segs + idx, segs + idx + 1,
			       (num_segs - idx - 1) * sizeof(*segs));
			num_segs--;
		} else {
			idx++;
		}
	}

	*segs_ret = segs;
	*num_segs_ret = num_segs;
	return TEE_SUCCESS;
}

static struct mobj *alloc_ta_mem(size_t size)
{
#ifdef CFG_PAGED_USER_TA
	return mobj_paged_alloc(size);
#else
	struct mobj *mobj = mobj_mm_alloc(mobj_sec_ddr, size, &tee_mm_sec_ddr);

	if (mobj)
		memset(mobj_get_va(mobj, 0), 0, size);
	return mobj;
#endif
}

static void init_utee_param(struct utee_params *up,
			const struct tee_ta_param *p, void *va[TEE_NUM_PARAMS])
{
	size_t n;

	up->types = p->types;
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uintptr_t a;
		uintptr_t b;

		switch (TEE_PARAM_TYPE_GET(p->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			a = (uintptr_t)va[n];
			b = p->u[n].mem.size;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -197,8 +197,12 @@
 #else
 	struct mobj *mobj = mobj_mm_alloc(mobj_sec_ddr, size, &tee_mm_sec_ddr);
 
-	if (mobj)
-		memset(mobj_get_va(mobj, 0), 0, size);
+	if (mobj) {
+		size_t granularity = BIT(tee_mm_sec_ddr.shift);
+
+		/* Round up to allocation granularity size */
+		memset(mobj_get_va(mobj, 0), 0, ROUNDUP(size, granularity));
+	}
 	return mobj;
 #endif
 }
```
