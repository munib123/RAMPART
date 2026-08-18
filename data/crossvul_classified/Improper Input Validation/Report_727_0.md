# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 727_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `727_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 740-780 of the vulnerable file.

			if (core_is_buffer_inside(pa, 1, p, size)) {
				/* Remove region offset (mobj phys offset) */
				ofs -= region->offset;
				/* Get offset-in-granule */
				p = pa - p;

				*va = (void *)(region->va + ofs + (vaddr_t)p);
				return TEE_SUCCESS;
			}
		}
	}

	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result tee_mmu_check_access_rights(const struct user_ta_ctx *utc,
				       uint32_t flags, uaddr_t uaddr,
				       size_t len)
{
	uaddr_t a;
	size_t addr_incr = MIN(CORE_MMU_USER_CODE_SIZE,
			       CORE_MMU_USER_PARAM_SIZE);

	if (ADD_OVERFLOW(uaddr, len, &a))
		return TEE_ERROR_ACCESS_DENIED;

	if ((flags & TEE_MEMORY_ACCESS_NONSECURE) &&
	    (flags & TEE_MEMORY_ACCESS_SECURE))
		return TEE_ERROR_ACCESS_DENIED;

	/*
	 * Rely on TA private memory test to check if address range is private
	 * to TA or not.
	 */
	if (!(flags & TEE_MEMORY_ACCESS_ANY_OWNER) &&
	   !tee_mmu_is_vbuf_inside_ta_private(utc, (void *)uaddr, len))
		return TEE_ERROR_ACCESS_DENIED;

	for (a = uaddr; a < (uaddr + len); a += addr_incr) {
		uint32_t attr;
		TEE_Result res;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -757,10 +757,11 @@
 				       size_t len)
 {
 	uaddr_t a;
+	uaddr_t end_addr = 0;
 	size_t addr_incr = MIN(CORE_MMU_USER_CODE_SIZE,
 			       CORE_MMU_USER_PARAM_SIZE);
 
-	if (ADD_OVERFLOW(uaddr, len, &a))
+	if (ADD_OVERFLOW(uaddr, len, &end_addr))
 		return TEE_ERROR_ACCESS_DENIED;
 
 	if ((flags & TEE_MEMORY_ACCESS_NONSECURE) &&
@@ -775,7 +776,7 @@
 	   !tee_mmu_is_vbuf_inside_ta_private(utc, (void *)uaddr, len))
 		return TEE_ERROR_ACCESS_DENIED;
 
-	for (a = uaddr; a < (uaddr + len); a += addr_incr) {
+	for (a = ROUNDDOWN(uaddr, addr_incr); a < end_addr; a += addr_incr) {
 		uint32_t attr;
 		TEE_Result res;
 
```
