# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2286_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2286_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 331-372 of the vulnerable file.

		*sum = csum_fold(csum_partial(diff, sizeof(diff),
				 ~csum_unfold(*sum)));
		if (skb->ip_summed == CHECKSUM_COMPLETE && pseudohdr)
			skb->csum = ~csum_partial(diff, sizeof(diff),
						  ~skb->csum);
	} else if (pseudohdr)
		*sum = ~csum_fold(csum_partial(diff, sizeof(diff),
				  csum_unfold(*sum)));
}
EXPORT_SYMBOL(inet_proto_csum_replace16);

struct __net_random_once_work {
	struct work_struct work;
	struct static_key *key;
};

static void __net_random_once_deferred(struct work_struct *w)
{
	struct __net_random_once_work *work =
		container_of(w, struct __net_random_once_work, work);
	if (!static_key_enabled(work->key))
		static_key_slow_inc(work->key);
	kfree(work);
}

static void __net_random_once_disable_jump(struct static_key *key)
{
	struct __net_random_once_work *w;

	w = kmalloc(sizeof(*w), GFP_ATOMIC);
	if (!w)
		return;

	INIT_WORK(&w->work, __net_random_once_deferred);
	w->key = key;
	schedule_work(&w->work);
}

bool __net_get_random_once(void *buf, int nbytes, bool *done,
			   struct static_key *done_key)
{
	static DEFINE_SPINLOCK(lock);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -348,8 +348,8 @@
 {
 	struct __net_random_once_work *work =
 		container_of(w, struct __net_random_once_work, work);
-	if (!static_key_enabled(work->key))
-		static_key_slow_inc(work->key);
+	BUG_ON(!static_key_enabled(work->key));
+	static_key_slow_dec(work->key);
 	kfree(work);
 }
 
@@ -367,7 +367,7 @@
 }
 
 bool __net_get_random_once(void *buf, int nbytes, bool *done,
-			   struct static_key *done_key)
+			   struct static_key *once_key)
 {
 	static DEFINE_SPINLOCK(lock);
 	unsigned long flags;
@@ -382,7 +382,7 @@
 	*done = true;
 	spin_unlock_irqrestore(&lock, flags);
 
-	__net_random_once_disable_jump(done_key);
+	__net_random_once_disable_jump(once_key);
 
 	return true;
 }
```
