# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2891_8
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2891_8`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 165-205 of the vulnerable file.

	n = key_serial_next(p, v);
	if (n)
		*_pos = key_node_serial(n);
	return n;
}

static void proc_keys_stop(struct seq_file *p, void *v)
	__releases(key_serial_lock)
{
	spin_unlock(&key_serial_lock);
}

static int proc_keys_show(struct seq_file *m, void *v)
{
	struct rb_node *_p = v;
	struct key *key = rb_entry(_p, struct key, serial_node);
	struct timespec now;
	unsigned long timo;
	key_ref_t key_ref, skey_ref;
	char xbuf[16];
	int rc;

	struct keyring_search_context ctx = {
		.index_key.type		= key->type,
		.index_key.description	= key->description,
		.cred			= m->file->f_cred,
		.match_data.cmp		= lookup_user_key_possessed,
		.match_data.raw_data	= key,
		.match_data.lookup_type	= KEYRING_SEARCH_LOOKUP_DIRECT,
		.flags			= KEYRING_SEARCH_NO_STATE_CHECK,
	};

	key_ref = make_key_ref(key, 0);

	/* determine if the key is possessed by this process (a test we can
	 * skip if the key does not indicate the possessor can view it
	 */
	if (key->perm & KEY_POS_VIEW) {
		skey_ref = search_my_process_keyrings(&ctx);
		if (!IS_ERR(skey_ref)) {
			key_ref_put(skey_ref);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -182,6 +182,7 @@
 	unsigned long timo;
 	key_ref_t key_ref, skey_ref;
 	char xbuf[16];
+	short state;
 	int rc;
 
 	struct keyring_search_context ctx = {
@@ -236,17 +237,19 @@
 			sprintf(xbuf, "%luw", timo / (60*60*24*7));
 	}
 
+	state = key_read_state(key);
+
 #define showflag(KEY, LETTER, FLAG) \
 	(test_bit(FLAG,	&(KEY)->flags) ? LETTER : '-')
 
 	seq_printf(m, "%08x %c%c%c%c%c%c%c %5d %4s %08x %5d %5d %-9.9s ",
 		   key->serial,
-		   showflag(key, 'I', KEY_FLAG_INSTANTIATED),
+		   state != KEY_IS_UNINSTANTIATED ? 'I' : '-',
 		   showflag(key, 'R', KEY_FLAG_REVOKED),
 		   showflag(key, 'D', KEY_FLAG_DEAD),
 		   showflag(key, 'Q', KEY_FLAG_IN_QUOTA),
 		   showflag(key, 'U', KEY_FLAG_USER_CONSTRUCT),
-		   showflag(key, 'N', KEY_FLAG_NEGATIVE),
+		   state < 0 ? 'N' : '-',
 		   showflag(key, 'i', KEY_FLAG_INVALIDATED),
 		   refcount_read(&key->usage),
 		   xbuf,
```
