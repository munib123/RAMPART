# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 405_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `405_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 135-175 of the vulnerable file.

	int err = 0;

	/* Our ID is an index into the kvm_regs struct. */
	off = core_reg_offset_from_id(reg->id);
	if (off >= nr_regs ||
	    (off + (KVM_REG_SIZE(reg->id) / sizeof(__u32))) >= nr_regs)
		return -ENOENT;

	if (validate_core_offset(reg))
		return -EINVAL;

	if (KVM_REG_SIZE(reg->id) > sizeof(tmp))
		return -EINVAL;

	if (copy_from_user(valp, uaddr, KVM_REG_SIZE(reg->id))) {
		err = -EFAULT;
		goto out;
	}

	if (off == KVM_REG_ARM_CORE_REG(regs.pstate)) {
		u32 mode = (*(u32 *)valp) & PSR_AA32_MODE_MASK;
		switch (mode) {
		case PSR_AA32_MODE_USR:
		case PSR_AA32_MODE_FIQ:
		case PSR_AA32_MODE_IRQ:
		case PSR_AA32_MODE_SVC:
		case PSR_AA32_MODE_ABT:
		case PSR_AA32_MODE_UND:
		case PSR_MODE_EL0t:
		case PSR_MODE_EL1t:
		case PSR_MODE_EL1h:
			break;
		default:
			err = -EINVAL;
			goto out;
		}
	}

	memcpy((u32 *)regs + off, valp, KVM_REG_SIZE(reg->id));
out:
	return err;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -152,17 +152,25 @@
 	}
 
 	if (off == KVM_REG_ARM_CORE_REG(regs.pstate)) {
-		u32 mode = (*(u32 *)valp) & PSR_AA32_MODE_MASK;
+		u64 mode = (*(u64 *)valp) & PSR_AA32_MODE_MASK;
 		switch (mode) {
 		case PSR_AA32_MODE_USR:
+			if (!system_supports_32bit_el0())
+				return -EINVAL;
+			break;
 		case PSR_AA32_MODE_FIQ:
 		case PSR_AA32_MODE_IRQ:
 		case PSR_AA32_MODE_SVC:
 		case PSR_AA32_MODE_ABT:
 		case PSR_AA32_MODE_UND:
+			if (!vcpu_el1_is_32bit(vcpu))
+				return -EINVAL;
+			break;
 		case PSR_MODE_EL0t:
 		case PSR_MODE_EL1t:
 		case PSR_MODE_EL1h:
+			if (vcpu_el1_is_32bit(vcpu))
+				return -EINVAL;
 			break;
 		default:
 			err = -EINVAL;
```
