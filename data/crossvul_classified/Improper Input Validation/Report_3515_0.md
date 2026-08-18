# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3515_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3515_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 576-616 of the vulnerable file.

		if (strcmp(command, "changehat") == 0) {
			error = aa_setprocattr_changehat(args, arg_size,
							 !AA_DO_TEST);
		} else if (strcmp(command, "permhat") == 0) {
			error = aa_setprocattr_changehat(args, arg_size,
							 AA_DO_TEST);
		} else if (strcmp(command, "changeprofile") == 0) {
			error = aa_setprocattr_changeprofile(args, !AA_ONEXEC,
							     !AA_DO_TEST);
		} else if (strcmp(command, "permprofile") == 0) {
			error = aa_setprocattr_changeprofile(args, !AA_ONEXEC,
							     AA_DO_TEST);
		} else if (strcmp(command, "permipc") == 0) {
			error = aa_setprocattr_permipc(args);
		} else {
			struct common_audit_data sa;
			COMMON_AUDIT_DATA_INIT(&sa, NONE);
			sa.aad.op = OP_SETPROCATTR;
			sa.aad.info = name;
			sa.aad.error = -EINVAL;
			return aa_audit(AUDIT_APPARMOR_DENIED, NULL, GFP_KERNEL,
					&sa, NULL);
		}
	} else if (strcmp(name, "exec") == 0) {
		error = aa_setprocattr_changeprofile(args, AA_ONEXEC,
						     !AA_DO_TEST);
	} else {
		/* only support the "current" and "exec" process attributes */
		return -EINVAL;
	}
	if (!error)
		error = size;
	return error;
}

static int apparmor_task_setrlimit(struct task_struct *task,
		unsigned int resource, struct rlimit *new_rlim)
{
	struct aa_profile *profile = aa_current_profile();
	int error = 0;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -593,7 +593,8 @@
 			sa.aad.op = OP_SETPROCATTR;
 			sa.aad.info = name;
 			sa.aad.error = -EINVAL;
-			return aa_audit(AUDIT_APPARMOR_DENIED, NULL, GFP_KERNEL,
+			return aa_audit(AUDIT_APPARMOR_DENIED,
+					__aa_current_profile(), GFP_KERNEL,
 					&sa, NULL);
 		}
 	} else if (strcmp(name, "exec") == 0) {
```
