# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5676_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5676_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1652-1692 of the vulnerable file.

		set_bit(MMF_DUMPABLE, &mm->flags);
		smp_wmb();
		clear_bit(MMF_DUMP_SECURELY, &mm->flags);
		break;
	case SUID_DUMP_ROOT:
		set_bit(MMF_DUMP_SECURELY, &mm->flags);
		smp_wmb();
		set_bit(MMF_DUMPABLE, &mm->flags);
		break;
	}
}

int __get_dumpable(unsigned long mm_flags)
{
	int ret;

	ret = mm_flags & MMF_DUMPABLE_MASK;
	return (ret > SUID_DUMP_USER) ? SUID_DUMP_ROOT : ret;
}

int get_dumpable(struct mm_struct *mm)
{
	return __get_dumpable(mm->flags);
}

SYSCALL_DEFINE3(execve,
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
	struct filename *path = getname(filename);
	int error = PTR_ERR(path);
	if (!IS_ERR(path)) {
		error = do_execve(path->name, argv, envp);
		putname(path);
	}
	return error;
}
#ifdef CONFIG_COMPAT
asmlinkage long compat_sys_execve(const char __user * filename,
	const compat_uptr_t __user * argv,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1669,6 +1669,12 @@
 	return (ret > SUID_DUMP_USER) ? SUID_DUMP_ROOT : ret;
 }
 
+/*
+ * This returns the actual value of the suid_dumpable flag. For things
+ * that are using this for checking for privilege transitions, it must
+ * test against SUID_DUMP_USER rather than treating it as a boolean
+ * value.
+ */
 int get_dumpable(struct mm_struct *mm)
 {
 	return __get_dumpable(mm->flags);
```
