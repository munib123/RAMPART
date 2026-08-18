# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2891_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2891_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 121-161 of the vulnerable file.

{
	return (struct key *) ((unsigned long) key_ref & ~1UL);
}

static inline bool is_key_possessed(const key_ref_t key_ref)
{
	return (unsigned long) key_ref & 1UL;
}

typedef int (*key_restrict_link_func_t)(struct key *dest_keyring,
					const struct key_type *type,
					const union key_payload *payload,
					struct key *restriction_key);

struct key_restriction {
	key_restrict_link_func_t check;
	struct key *key;
	struct key_type *keytype;
};

/*****************************************************************************/
/*
 * authentication token / access credential / keyring
 * - types of key include:
 *   - keyrings
 *   - disk encryption IDs
 *   - Kerberos TGTs and tickets
 */
struct key {
	refcount_t		usage;		/* number of references */
	key_serial_t		serial;		/* key serial number */
	union {
		struct list_head graveyard_link;
		struct rb_node	serial_node;
	};
	struct rw_semaphore	sem;		/* change vs change sem */
	struct key_user		*user;		/* owner of this key */
	void			*security;	/* security data for this key */
	union {
		time_t		expiry;		/* time at which key expires (or 0) */
		time_t		revoked_at;	/* time at which key was revoked */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,6 +136,11 @@
 	key_restrict_link_func_t check;
 	struct key *key;
 	struct key_type *keytype;
+};
+
+enum key_state {
+	KEY_IS_UNINSTANTIATED,
+	KEY_IS_POSITIVE,		/* Positively instantiated */
 };
 
 /*****************************************************************************/
@@ -169,6 +174,7 @@
 						 * - may not match RCU dereferenced payload
 						 * - payload should contain own length
 						 */
+	short			state;		/* Key state (+) or rejection error (-) */
 
 #ifdef KEY_DEBUGGING
 	unsigned		magic;
@@ -176,18 +182,16 @@
 #endif
 
 	unsigned long		flags;		/* status flags (change with bitops) */
-#define KEY_FLAG_INSTANTIATED	0	/* set if key has been instantiated */
-#define KEY_FLAG_DEAD		1	/* set if key type has been deleted */
-#define KEY_FLAG_REVOKED	2	/* set if key had been revoked */
-#define KEY_FLAG_IN_QUOTA	3	/* set if key consumes quota */
-#define KEY_FLAG_USER_CONSTRUCT	4	/* set if key is being constructed in userspace */
-#define KEY_FLAG_NEGATIVE	5	/* set if key is negative */
-#define KEY_FLAG_ROOT_CAN_CLEAR	6	/* set if key can be cleared by root without permission */
-#define KEY_FLAG_INVALIDATED	7	/* set if key has been invalidated */
-#define KEY_FLAG_BUILTIN	8	/* set if key is built in to the kernel */
-#define KEY_FLAG_ROOT_CAN_INVAL	9	/* set if key can be invalidated by root without permission */
-#define KEY_FLAG_KEEP		10	/* set if key should not be removed */
-#define KEY_FLAG_UID_KEYRING	11	/* set if key is a user or user session keyring */
+#define KEY_FLAG_DEAD		0	/* set if key type has been deleted */
+#define KEY_FLAG_REVOKED	1	/* set if key had been revoked */
+#define KEY_FLAG_IN_QUOTA	2	/* set if key consumes quota */
+#define KEY_FLAG_USER_CONSTRUCT	3	/* set if key is being constructed in userspace */
+#define KEY_FLAG_ROOT_CAN_CLEAR	4	/* set if key can be cleared by root without permission */
+#define KEY_FLAG_INVALIDATED	5	/* set if key has been invalidated */
+#define KEY_FLAG_BUILTIN	6	/* set if key is built in to the kernel */
+#define KEY_FLAG_ROOT_CAN_INVAL	7	/* set if key can be invalidated by root without permission */
+#define KEY_FLAG_KEEP		8	/* set if key should not be removed */
+#define KEY_FLAG_UID_KEYRING	9	/* set if key is a user or user session keyring */
 
 	/* the key type and key description string
 	 * - the desc is used to match a key against search criteria
@@ -213,7 +217,6 @@
 			struct list_head name_link;
 			struct assoc_array keys;
 		};
-		int reject_error;
 	};
 
 	/* This is set on a keyring to restrict the addition of a link to a key
@@ -353,17 +356,27 @@
 #define	KEY_NEED_SETATTR 0x20	/* Require permission to change attributes */
 #define	KEY_NEED_ALL	0x3f	/* All the above permissions */
 
+static inline short key_read_state(const struct key *key)
+{
+	/* Barrier versus mark_key_instantiated(). */
+	return smp_load_acquire(&key->state);
+}
+
 /**
- * key_is_instantiated - Determine if a key has been positively instantiated
+ * key_is_positive - Determine if a key has been positively instantiated
  * @key: The key to check.
  *
  * Return true if the specified key has been positively instantiated, false
  * otherwise.
  */
-static inline bool key_is_instantiated(const struct key *key)
-{
-	return test_bit(KEY_FLAG_INSTANTIATED, &key->flags) &&
-		!test_bit(KEY_FLAG_NEGATIVE, &key->flags);
+static inline bool key_is_positive(const struct key *key)
+{
+	return key_read_state(key) == KEY_IS_POSITIVE;
+}
+
+static inline bool key_is_negative(const struct key *key)
+{
+	return key_read_state(key) < 0;
 }
 
 #define dereference_key_rcu(KEY)					\
```
