# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3224_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3224_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 127-167 of the vulnerable file.

	}
	return NULL;
}

static struct ucounts *get_ucounts(struct user_namespace *ns, kuid_t uid)
{
	struct hlist_head *hashent = ucounts_hashentry(ns, uid);
	struct ucounts *ucounts, *new;

	spin_lock_irq(&ucounts_lock);
	ucounts = find_ucounts(ns, uid, hashent);
	if (!ucounts) {
		spin_unlock_irq(&ucounts_lock);

		new = kzalloc(sizeof(*new), GFP_KERNEL);
		if (!new)
			return NULL;

		new->ns = ns;
		new->uid = uid;
		atomic_set(&new->count, 0);

		spin_lock_irq(&ucounts_lock);
		ucounts = find_ucounts(ns, uid, hashent);
		if (ucounts) {
			kfree(new);
		} else {
			hlist_add_head(&new->node, hashent);
			ucounts = new;
		}
	}
	if (!atomic_add_unless(&ucounts->count, 1, INT_MAX))
		ucounts = NULL;
	spin_unlock_irq(&ucounts_lock);
	return ucounts;
}

static void put_ucounts(struct ucounts *ucounts)
{
	unsigned long flags;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -144,7 +144,7 @@
 
 		new->ns = ns;
 		new->uid = uid;
-		atomic_set(&new->count, 0);
+		new->count = 0;
 
 		spin_lock_irq(&ucounts_lock);
 		ucounts = find_ucounts(ns, uid, hashent);
@@ -155,8 +155,10 @@
 			ucounts = new;
 		}
 	}
-	if (!atomic_add_unless(&ucounts->count, 1, INT_MAX))
+	if (ucounts->count == INT_MAX)
 		ucounts = NULL;
+	else
+		ucounts->count += 1;
 	spin_unlock_irq(&ucounts_lock);
 	return ucounts;
 }
@@ -165,13 +167,15 @@
 {
 	unsigned long flags;
 
-	if (atomic_dec_and_test(&ucounts->count)) {
-		spin_lock_irqsave(&ucounts_lock, flags);
+	spin_lock_irqsave(&ucounts_lock, flags);
+	ucounts->count -= 1;
+	if (!ucounts->count)
 		hlist_del_init(&ucounts->node);
-		spin_unlock_irqrestore(&ucounts_lock, flags);
-
-		kfree(ucounts);
-	}
+	else
+		ucounts = NULL;
+	spin_unlock_irqrestore(&ucounts_lock, flags);
+
+	kfree(ucounts);
 }
 
 static inline bool atomic_inc_below(atomic_t *v, int u)
```
