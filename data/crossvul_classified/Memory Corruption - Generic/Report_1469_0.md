# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1469_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1469_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1164-1206 of the vulnerable file.

	*_edit = NULL;
}

/*
 * Finish linking a key into to a keyring.
 *
 * Must be called with __key_link_begin() having being called.
 */
void __key_link_end(struct key *keyring,
		    const struct keyring_index_key *index_key,
		    struct assoc_array_edit *edit)
	__releases(&keyring->sem)
	__releases(&keyring_serialise_link_sem)
{
	BUG_ON(index_key->type == NULL);
	kenter("%d,%s,", keyring->serial, index_key->type->name);

	if (index_key->type == &key_type_keyring)
		up_write(&keyring_serialise_link_sem);

	if (edit && !edit->dead_leaf) {
		key_payload_reserve(keyring,
				    keyring->datalen - KEYQUOTA_LINK_BYTES);
		assoc_array_cancel_edit(edit);
	}
	up_write(&keyring->sem);
}

/**
 * key_link - Link a key to a keyring
 * @keyring: The keyring to make the link in.
 * @key: The key to link to.
 *
 * Make a link in a keyring to a key, such that the keyring holds a reference
 * on that key and the key can potentially be found by searching that keyring.
 *
 * This function will write-lock the keyring's semaphore and will consume some
 * of the user's key data quota to hold the link.
 *
 * Returns 0 if successful, -ENOTDIR if the keyring isn't a keyring,
 * -EKEYREVOKED if the keyring has been revoked, -ENFILE if the keyring is
 * full, -EDQUOT if there is insufficient key data quota remaining to add
 * another link or -ENOMEM if there's insufficient memory.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1181,9 +1181,11 @@
 	if (index_key->type == &key_type_keyring)
 		up_write(&keyring_serialise_link_sem);
 
-	if (edit && !edit->dead_leaf) {
-		key_payload_reserve(keyring,
-				    keyring->datalen - KEYQUOTA_LINK_BYTES);
+	if (edit) {
+		if (!edit->dead_leaf) {
+			key_payload_reserve(keyring,
+				keyring->datalen - KEYQUOTA_LINK_BYTES);
+		}
 		assoc_array_cancel_edit(edit);
 	}
 	up_write(&keyring->sem);
```
