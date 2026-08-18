# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3337_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3337_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 882-922 of the vulnerable file.

	assert(wrk->handling == VCL_RET_DELIVER);

	bo->vfc->bo = bo;
	bo->vfc->wrk = bo->wrk;
	bo->vfc->oc = bo->fetch_objcore;
	bo->vfc->http = bo->beresp;
	bo->vfc->esi_req = bo->bereq;

	if (vbf_beresp2obj(bo)) {
		(void)VFP_Error(bo->vfc, "Could not get storage");
		VSB_destroy(&synth_body);
		return (F_STP_FAIL);
	}

	ll = VSB_len(synth_body);
	o = 0;
	while (ll > 0) {
		l = ll;
		if (VFP_GetStorage(bo->vfc, &l, &ptr) != VFP_OK)
			break;
		memcpy(ptr, VSB_data(synth_body) + o, l);
		VFP_Extend(bo->vfc, l);
		ll -= l;
		o += l;
	}
	AZ(ObjSetU64(wrk, bo->fetch_objcore, OA_LEN, o));
	VSB_destroy(&synth_body);
	HSH_Unbusy(wrk, bo->fetch_objcore);
	ObjSetState(wrk, bo->fetch_objcore, BOS_FINISHED);
	return (F_STP_DONE);
}

/*--------------------------------------------------------------------
 */

static enum fetch_step
vbf_stp_fail(struct worker *wrk, const struct busyobj *bo)
{
	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(bo, BUSYOBJ_MAGIC);
	CHECK_OBJ_NOTNULL(bo->fetch_objcore, OBJCORE_MAGIC);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -899,6 +899,8 @@
 		l = ll;
 		if (VFP_GetStorage(bo->vfc, &l, &ptr) != VFP_OK)
 			break;
+		if (l > ll)
+			l = ll;
 		memcpy(ptr, VSB_data(synth_body) + o, l);
 		VFP_Extend(bo->vfc, l);
 		ll -= l;
```
