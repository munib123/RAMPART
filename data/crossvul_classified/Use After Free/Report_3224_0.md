# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3224_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3224_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 55-95 of the vulnerable file.

	unsigned long		flags;

	/* Register of per-UID persistent keyrings for this namespace */
#ifdef CONFIG_PERSISTENT_KEYRINGS
	struct key		*persistent_keyring_register;
	struct rw_semaphore	persistent_keyring_register_sem;
#endif
	struct work_struct	work;
#ifdef CONFIG_SYSCTL
	struct ctl_table_set	set;
	struct ctl_table_header *sysctls;
#endif
	struct ucounts		*ucounts;
	int ucount_max[UCOUNT_COUNTS];
};

struct ucounts {
	struct hlist_node node;
	struct user_namespace *ns;
	kuid_t uid;
	atomic_t count;
	atomic_t ucount[UCOUNT_COUNTS];
};

extern struct user_namespace init_user_ns;

bool setup_userns_sysctls(struct user_namespace *ns);
void retire_userns_sysctls(struct user_namespace *ns);
struct ucounts *inc_ucount(struct user_namespace *ns, kuid_t uid, enum ucount_type type);
void dec_ucount(struct ucounts *ucounts, enum ucount_type type);

#ifdef CONFIG_USER_NS

static inline struct user_namespace *get_user_ns(struct user_namespace *ns)
{
	if (ns)
		atomic_inc(&ns->count);
	return ns;
}

extern int create_user_ns(struct cred *new);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,7 +72,7 @@
 	struct hlist_node node;
 	struct user_namespace *ns;
 	kuid_t uid;
-	atomic_t count;
+	int count;
 	atomic_t ucount[UCOUNT_COUNTS];
 };
 
```
