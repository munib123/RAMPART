# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2423_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2423_4`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 832-872 of the vulnerable file.

			break;

		case PTRACE_SETFPREGS:
			ret = copy_regset_from_user(child,
						    &user_arm_view, REGSET_FPR,
						    0, sizeof(union fp_state),
						    datap);
			break;

#ifdef CONFIG_IWMMXT
		case PTRACE_GETWMMXREGS:
			ret = ptrace_getwmmxregs(child, datap);
			break;

		case PTRACE_SETWMMXREGS:
			ret = ptrace_setwmmxregs(child, datap);
			break;
#endif

		case PTRACE_GET_THREAD_AREA:
			ret = put_user(task_thread_info(child)->tp_value,
				       datap);
			break;

		case PTRACE_SET_SYSCALL:
			task_thread_info(child)->syscall = data;
			ret = 0;
			break;

#ifdef CONFIG_CRUNCH
		case PTRACE_GETCRUNCHREGS:
			ret = ptrace_getcrunchregs(child, datap);
			break;

		case PTRACE_SETCRUNCHREGS:
			ret = ptrace_setcrunchregs(child, datap);
			break;
#endif

#ifdef CONFIG_VFP
		case PTRACE_GETVFPREGS:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -849,7 +849,7 @@
 #endif
 
 		case PTRACE_GET_THREAD_AREA:
-			ret = put_user(task_thread_info(child)->tp_value,
+			ret = put_user(task_thread_info(child)->tp_value[0],
 				       datap);
 			break;
 
```
