# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3060_5
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3060_5`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 19-53 of the vulnerable file.

/*
 * the payload for a key of type "user" or "logon"
 * - once filled in and attached to a key:
 *   - the payload struct is invariant may not be changed, only replaced
 *   - the payload must be read with RCU procedures or with the key semaphore
 *     held
 *   - the payload may only be replaced with the key semaphore write-locked
 * - the key's data length is the size of the actual data, not including the
 *   payload wrapper
 */
struct user_key_payload {
	struct rcu_head	rcu;		/* RCU destructor */
	unsigned short	datalen;	/* length of this data */
	char		data[0];	/* actual data */
};

extern struct key_type key_type_user;
extern struct key_type key_type_logon;

struct key_preparsed_payload;
struct key_match_data;

extern int user_preparse(struct key_preparsed_payload *prep);
extern void user_free_preparse(struct key_preparsed_payload *prep);
extern int user_update(struct key *key, struct key_preparsed_payload *prep);
extern int user_match(const struct key *key,
		      const struct key_match_data *match_data);
extern void user_revoke(struct key *key);
extern void user_destroy(struct key *key);
extern void user_describe(const struct key *user, struct seq_file *m);
extern long user_read(const struct key *key,
		      char __user *buffer, size_t buflen);


#endif /* _KEYS_USER_TYPE_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,13 +36,10 @@
 extern struct key_type key_type_logon;
 
 struct key_preparsed_payload;
-struct key_match_data;
 
 extern int user_preparse(struct key_preparsed_payload *prep);
 extern void user_free_preparse(struct key_preparsed_payload *prep);
 extern int user_update(struct key *key, struct key_preparsed_payload *prep);
-extern int user_match(const struct key *key,
-		      const struct key_match_data *match_data);
 extern void user_revoke(struct key *key);
 extern void user_destroy(struct key *key);
 extern void user_describe(const struct key *user, struct seq_file *m);
```
