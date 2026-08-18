# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1625_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1625_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 69-109 of the vulnerable file.

#else
# define LDSEM_ACTIVE_MASK	0x0000ffffL
#endif

#define LDSEM_UNLOCKED		0L
#define LDSEM_ACTIVE_BIAS	1L
#define LDSEM_WAIT_BIAS		(-LDSEM_ACTIVE_MASK-1)
#define LDSEM_READ_BIAS		LDSEM_ACTIVE_BIAS
#define LDSEM_WRITE_BIAS	(LDSEM_WAIT_BIAS + LDSEM_ACTIVE_BIAS)

struct ldsem_waiter {
	struct list_head list;
	struct task_struct *task;
};

static inline long ldsem_atomic_update(long delta, struct ld_semaphore *sem)
{
	return atomic_long_add_return(delta, (atomic_long_t *)&sem->count);
}

static inline int ldsem_cmpxchg(long *old, long new, struct ld_semaphore *sem)
{
	long tmp = *old;
	*old = atomic_long_cmpxchg(&sem->count, *old, new);
	return *old == tmp;
}

/*
 * Initialize an ldsem:
 */
void __init_ldsem(struct ld_semaphore *sem, const char *name,
		  struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	/*
	 * Make sure we are not reinitializing a held semaphore:
	 */
	debug_check_no_locks_freed((void *)sem, sizeof(*sem));
	lockdep_init_map(&sem->dep_map, name, key, 0);
#endif
	sem->count = LDSEM_UNLOCKED;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,11 +86,21 @@
 	return atomic_long_add_return(delta, (atomic_long_t *)&sem->count);
 }
 
+/*
+ * ldsem_cmpxchg() updates @*old with the last-known sem->count value.
+ * Returns 1 if count was successfully changed; @*old will have @new value.
+ * Returns 0 if count was not changed; @*old will have most recent sem->count
+ */
 static inline int ldsem_cmpxchg(long *old, long new, struct ld_semaphore *sem)
 {
-	long tmp = *old;
-	*old = atomic_long_cmpxchg(&sem->count, *old, new);
-	return *old == tmp;
+	long tmp = atomic_long_cmpxchg(&sem->count, *old, new);
+	if (tmp == *old) {
+		*old = new;
+		return 1;
+	} else {
+		*old = tmp;
+		return 0;
+	}
 }
 
 /*
```
