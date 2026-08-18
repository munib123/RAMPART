# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2858_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2858_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 627-668 of the vulnerable file.

		r = KVM_MAX_VCPUS;
		break;
#ifdef CONFIG_PPC_BOOK3S_64
	case KVM_CAP_PPC_GET_SMMU_INFO:
		r = 1;
		break;
	case KVM_CAP_SPAPR_MULTITCE:
		r = 1;
		break;
	case KVM_CAP_SPAPR_RESIZE_HPT:
		/* Disable this on POWER9 until code handles new HPTE format */
		r = !!hv_enabled && !cpu_has_feature(CPU_FTR_ARCH_300);
		break;
#endif
#ifdef CONFIG_KVM_BOOK3S_HV_POSSIBLE
	case KVM_CAP_PPC_FWNMI:
		r = hv_enabled;
		break;
#endif
	case KVM_CAP_PPC_HTM:
		r = cpu_has_feature(CPU_FTR_TM_COMP) &&
		    is_kvmppc_hv_enabled(kvm);
		break;
	default:
		r = 0;
		break;
	}
	return r;

}

long kvm_arch_dev_ioctl(struct file *filp,
                        unsigned int ioctl, unsigned long arg)
{
	return -EINVAL;
}

void kvm_arch_free_memslot(struct kvm *kvm, struct kvm_memory_slot *free,
			   struct kvm_memory_slot *dont)
{
	kvmppc_core_free_memslot(kvm, free, dont);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -644,8 +644,7 @@
 		break;
 #endif
 	case KVM_CAP_PPC_HTM:
-		r = cpu_has_feature(CPU_FTR_TM_COMP) &&
-		    is_kvmppc_hv_enabled(kvm);
+		r = cpu_has_feature(CPU_FTR_TM_COMP) && hv_enabled;
 		break;
 	default:
 		r = 0;
```
