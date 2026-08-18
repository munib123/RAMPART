# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2162_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2162_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 370-410 of the vulnerable file.

#define AR_P_MASK (1 << 7)
#define AR_L_MASK (1 << 13)
#define AR_DB_MASK (1 << 14)
#define AR_G_MASK (1 << 15)
#define AR_DPL_SHIFT 5
#define AR_DPL(ar) (((ar) >> AR_DPL_SHIFT) & 3)

#define AR_RESERVD_MASK 0xfffe0f00

#define TSS_PRIVATE_MEMSLOT			(KVM_USER_MEM_SLOTS + 0)
#define APIC_ACCESS_PAGE_PRIVATE_MEMSLOT	(KVM_USER_MEM_SLOTS + 1)
#define IDENTITY_PAGETABLE_PRIVATE_MEMSLOT	(KVM_USER_MEM_SLOTS + 2)

#define VMX_NR_VPIDS				(1 << 16)
#define VMX_VPID_EXTENT_SINGLE_CONTEXT		1
#define VMX_VPID_EXTENT_ALL_CONTEXT		2

#define VMX_EPT_EXTENT_INDIVIDUAL_ADDR		0
#define VMX_EPT_EXTENT_CONTEXT			1
#define VMX_EPT_EXTENT_GLOBAL			2

#define VMX_EPT_EXECUTE_ONLY_BIT		(1ull)
#define VMX_EPT_PAGE_WALK_4_BIT			(1ull << 6)
#define VMX_EPTP_UC_BIT				(1ull << 8)
#define VMX_EPTP_WB_BIT				(1ull << 14)
#define VMX_EPT_2MB_PAGE_BIT			(1ull << 16)
#define VMX_EPT_1GB_PAGE_BIT			(1ull << 17)
#define VMX_EPT_AD_BIT				    (1ull << 21)
#define VMX_EPT_EXTENT_CONTEXT_BIT		(1ull << 25)
#define VMX_EPT_EXTENT_GLOBAL_BIT		(1ull << 26)

#define VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT      (1ull << 9) /* (41 - 32) */
#define VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT      (1ull << 10) /* (42 - 32) */

#define VMX_EPT_DEFAULT_GAW			3
#define VMX_EPT_MAX_GAW				0x4
#define VMX_EPT_MT_EPTE_SHIFT			3
#define VMX_EPT_GAW_EPTP_SHIFT			3
#define VMX_EPT_AD_ENABLE_BIT			(1ull << 6)
#define VMX_EPT_DEFAULT_MT			0x6ull
#define VMX_EPT_READABLE_MASK			0x1ull
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -387,6 +387,7 @@
 #define VMX_EPT_EXTENT_INDIVIDUAL_ADDR		0
 #define VMX_EPT_EXTENT_CONTEXT			1
 #define VMX_EPT_EXTENT_GLOBAL			2
+#define VMX_EPT_EXTENT_SHIFT			24
 
 #define VMX_EPT_EXECUTE_ONLY_BIT		(1ull)
 #define VMX_EPT_PAGE_WALK_4_BIT			(1ull << 6)
@@ -394,6 +395,7 @@
 #define VMX_EPTP_WB_BIT				(1ull << 14)
 #define VMX_EPT_2MB_PAGE_BIT			(1ull << 16)
 #define VMX_EPT_1GB_PAGE_BIT			(1ull << 17)
+#define VMX_EPT_INVEPT_BIT			(1ull << 20)
 #define VMX_EPT_AD_BIT				    (1ull << 21)
 #define VMX_EPT_EXTENT_CONTEXT_BIT		(1ull << 25)
 #define VMX_EPT_EXTENT_GLOBAL_BIT		(1ull << 26)
```
