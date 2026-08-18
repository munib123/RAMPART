# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2155_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2155_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 803-843 of the vulnerable file.

		goto out;
	*info = inp;
	inp += *count;
	*count += sh.sh_properties;
	p = CAST(const uint8_t *, (const void *)
	    ((const char *)(const void *)sst->sst_tab +
	    offs + sizeof(sh)));
	e = CAST(const uint8_t *, (const void *)
	    (((const char *)(const void *)shp) + sh.sh_len));
	if (cdf_check_stream_offset(sst, h, e, 0, __LINE__) == -1)
		goto out;
	for (i = 0; i < sh.sh_properties; i++) {
		size_t ofs, tail = (i << 1) + 1;
		if (cdf_check_stream_offset(sst, h, p, tail * sizeof(uint32_t),
		    __LINE__) == -1)
			goto out;
		ofs = CDF_GETUINT32(p, tail);
		q = (const uint8_t *)(const void *)
		    ((const char *)(const void *)p + ofs
		    - 2 * sizeof(uint32_t));
		if (q > e) {
			DPRINTF(("Ran of the end %p > %p\n", q, e));
			goto out;
		}
		inp[i].pi_id = CDF_GETUINT32(p, i << 1);
		inp[i].pi_type = CDF_GETUINT32(q, 0);
		DPRINTF(("%" SIZE_T_FORMAT "u) id=%x type=%x offs=0x%tx,0x%x\n",
		    i, inp[i].pi_id, inp[i].pi_type, q - p, offs));
		if (inp[i].pi_type & CDF_VECTOR) {
			nelements = CDF_GETUINT32(q, 1);
			if (nelements == 0) {
				DPRINTF(("CDF_VECTOR with nelements == 0\n"));
				goto out;
			}
			o = 2;
		} else {
			nelements = 1;
			o = 1;
		}
		o4 = o * sizeof(uint32_t);
		if (inp[i].pi_type & (CDF_ARRAY|CDF_BYREF|CDF_RESERVED))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -820,7 +820,7 @@
 		q = (const uint8_t *)(const void *)
 		    ((const char *)(const void *)p + ofs
 		    - 2 * sizeof(uint32_t));
-		if (q > e) {
+		if (q < p || q > e) {
 			DPRINTF(("Ran of the end %p > %p\n", q, e));
 			goto out;
 		}
```
