# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3060_6
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3060_6`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 96-139 of the vulnerable file.


	/* instantiate a key of this type
	 * - this method should call key_payload_reserve() to determine if the
	 *   user's quota will hold the payload
	 */
	int (*instantiate)(struct key *key, struct key_preparsed_payload *prep);

	/* update a key of this type (optional)
	 * - this method should call key_payload_reserve() to recalculate the
	 *   quota consumption
	 * - the key must be locked against read when modifying
	 */
	int (*update)(struct key *key, struct key_preparsed_payload *prep);

	/* Preparse the data supplied to ->match() (optional).  The
	 * data to be preparsed can be found in match_data->raw_data.
	 * The lookup type can also be set by this function.
	 */
	int (*match_preparse)(struct key_match_data *match_data);

	/* match a key against a description */
	int (*match)(const struct key *key,
		     const struct key_match_data *match_data);

	/* Free preparsed match data (optional).  This should be supplied it
	 * ->match_preparse() is supplied. */
	void (*match_free)(struct key_match_data *match_data);

	/* clear some of the data from a key on revokation (optional)
	 * - the key's semaphore will be write-locked by the caller
	 */
	void (*revoke)(struct key *key);

	/* clear the data from a key (optional) */
	void (*destroy)(struct key *key);

	/* describe a key */
	void (*describe)(const struct key *key, struct seq_file *p);

	/* read a key's data (optional)
	 * - permission checks will be done by the caller
	 * - the key's semaphore will be readlocked by the caller
	 * - should return the amount of data that could be read, no matter how
	 *   much is copied into the buffer
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -113,10 +113,6 @@
 	 */
 	int (*match_preparse)(struct key_match_data *match_data);
 
-	/* match a key against a description */
-	int (*match)(const struct key *key,
-		     const struct key_match_data *match_data);
-
 	/* Free preparsed match data (optional).  This should be supplied it
 	 * ->match_preparse() is supplied. */
 	void (*match_free)(struct key_match_data *match_data);
```
