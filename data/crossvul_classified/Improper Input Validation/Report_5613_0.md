# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5613_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5613_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 168-208 of the vulnerable file.

		offset    = index * sizeof(pt_element_t);
		pte_gpa   = gfn_to_gpa(table_gfn) + offset;
		walker->table_gfn[walker->level - 1] = table_gfn;
		walker->pte_gpa[walker->level - 1] = pte_gpa;

		real_gfn = mmu->translate_gpa(vcpu, gfn_to_gpa(table_gfn),
					      PFERR_USER_MASK|PFERR_WRITE_MASK);
		if (unlikely(real_gfn == UNMAPPED_GVA)) {
			present = false;
			break;
		}
		real_gfn = gpa_to_gfn(real_gfn);

		host_addr = gfn_to_hva(vcpu->kvm, real_gfn);
		if (unlikely(kvm_is_error_hva(host_addr))) {
			present = false;
			break;
		}

		ptep_user = (pt_element_t __user *)((void *)host_addr + offset);
		if (unlikely(copy_from_user(&pte, ptep_user, sizeof(pte)))) {
			present = false;
			break;
		}

		trace_kvm_mmu_paging_element(pte, walker->level);

		if (unlikely(!is_present_gpte(pte))) {
			present = false;
			break;
		}

		if (unlikely(is_rsvd_bits_set(&vcpu->arch.mmu, pte,
					      walker->level))) {
			rsvd_fault = true;
			break;
		}

		if (unlikely(write_fault && !is_writable_pte(pte)
			     && (user_fault || is_write_protection(vcpu))))
			eperm = true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -185,7 +185,7 @@
 		}
 
 		ptep_user = (pt_element_t __user *)((void *)host_addr + offset);
-		if (unlikely(copy_from_user(&pte, ptep_user, sizeof(pte)))) {
+		if (unlikely(__copy_from_user(&pte, ptep_user, sizeof(pte)))) {
 			present = false;
 			break;
 		}
```
