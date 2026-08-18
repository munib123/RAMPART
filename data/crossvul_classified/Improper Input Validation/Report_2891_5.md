# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2891_5
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2891_5`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 385-425 of the vulnerable file.

		    (key->user->qnbytes + delta >= maxbytes ||
		     key->user->qnbytes + delta < key->user->qnbytes)) {
			ret = -EDQUOT;
		}
		else {
			key->user->qnbytes += delta;
			key->quotalen += delta;
		}
		spin_unlock(&key->user->lock);
	}

	/* change the recorded data length if that didn't generate an error */
	if (ret == 0)
		key->datalen = datalen;

	return ret;
}
EXPORT_SYMBOL(key_payload_reserve);

/*
 * Instantiate a key and link it into the target keyring atomically.  Must be
 * called with the target keyring's semaphore writelocked.  The target key's
 * semaphore need not be locked as instantiation is serialised by
 * key_construction_mutex.
 */
static int __key_instantiate_and_link(struct key *key,
				      struct key_preparsed_payload *prep,
				      struct key *keyring,
				      struct key *authkey,
				      struct assoc_array_edit **_edit)
{
	int ret, awaken;

	key_check(key);
	key_check(keyring);

	awaken = 0;
	ret = -EBUSY;

	mutex_lock(&key_construction_mutex);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -402,6 +402,18 @@
 EXPORT_SYMBOL(key_payload_reserve);
 
 /*
+ * Change the key state to being instantiated.
+ */
+static void mark_key_instantiated(struct key *key, int reject_error)
+{
+	/* Commit the payload before setting the state; barrier versus
+	 * key_read_state().
+	 */
+	smp_store_release(&key->state,
+			  (reject_error < 0) ? reject_error : KEY_IS_POSITIVE);
+}
+
+/*
  * Instantiate a key and link it into the target keyring atomically.  Must be
  * called with the target keyring's semaphore writelocked.  The target key's
  * semaphore need not be locked as instantiation is serialised by
@@ -424,14 +436,14 @@
 	mutex_lock(&key_construction_mutex);
 
 	/* can't instantiate twice */
-	if (!test_bit(KEY_FLAG_INSTANTIATED, &key->flags)) {
+	if (key->state == KEY_IS_UNINSTANTIATED) {
 		/* instantiate the key */
 		ret = key->type->instantiate(key, prep);
 
 		if (ret == 0) {
 			/* mark the key as being instantiated */
 			atomic_inc(&key->user->nikeys);
-			set_bit(KEY_FLAG_INSTANTIATED, &key->flags);
+			mark_key_instantiated(key, 0);
 
 			if (test_and_clear_bit(KEY_FLAG_USER_CONSTRUCT, &key->flags))
 				awaken = 1;
@@ -577,13 +589,10 @@
 	mutex_lock(&key_construction_mutex);
 
 	/* can't instantiate twice */
-	if (!test_bit(KEY_FLAG_INSTANTIATED, &key->flags)) {
+	if (key->state == KEY_IS_UNINSTANTIATED) {
 		/* mark the key as being negatively instantiated */
 		atomic_inc(&key->user->nikeys);
-		key->reject_error = -error;
-		smp_wmb();
-		set_bit(KEY_FLAG_NEGATIVE, &key->flags);
-		set_bit(KEY_FLAG_INSTANTIATED, &key->flags);
+		mark_key_instantiated(key, -error);
 		now = current_kernel_time();
 		key->expiry = now.tv_sec + timeout;
 		key_schedule_gc(key->expiry + key_gc_delay);
@@ -752,8 +761,8 @@
 
 	ret = key->type->update(key, prep);
 	if (ret == 0)
-		/* updating a negative key instantiates it */
-		clear_bit(KEY_FLAG_NEGATIVE, &key->flags);
+		/* Updating a negative key positively instantiates it */
+		mark_key_instantiated(key, 0);
 
 	up_write(&key->sem);
 
@@ -986,8 +995,8 @@
 
 	ret = key->type->update(key, &prep);
 	if (ret == 0)
-		/* updating a negative key instantiates it */
-		clear_bit(KEY_FLAG_NEGATIVE, &key->flags);
+		/* Updating a negative key positively instantiates it */
+		mark_key_instantiated(key, 0);
 
 	up_write(&key->sem);
 
```
