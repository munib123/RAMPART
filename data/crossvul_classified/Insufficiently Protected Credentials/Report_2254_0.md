# CrossVul Fix Pair: Credentials Management Errors in c
**Pair ID:** 2254_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2254_0`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```c
Lines 325-365 of the vulnerable file.

 */
static void
check_1_6_dummy(kadm5_principal_ent_t entry, long mask,
                int n_ks_tuple, krb5_key_salt_tuple *ks_tuple, char **passptr)
{
    int i;
    char *password = *passptr;

    /* Old-style randkey operations disallowed tickets to start. */
    if (password == NULL || !(mask & KADM5_ATTRIBUTES) ||
        !(entry->attributes & KRB5_KDB_DISALLOW_ALL_TIX))
        return;

    /* The 1.6 dummy password was the octets 1..255. */
    for (i = 0; (unsigned char) password[i] == i + 1; i++);
    if (password[i] != '\0' || i != 255)
        return;

    /* This will make the caller use a random password instead. */
    *passptr = NULL;
}

kadm5_ret_t
kadm5_create_principal(void *server_handle,
                       kadm5_principal_ent_t entry, long mask,
                       char *password)
{
    return
        kadm5_create_principal_3(server_handle, entry, mask,
                                 0, NULL, password);
}
kadm5_ret_t
kadm5_create_principal_3(void *server_handle,
                         kadm5_principal_ent_t entry, long mask,
                         int n_ks_tuple, krb5_key_salt_tuple *ks_tuple,
                         char *password)
{
    krb5_db_entry               *kdb;
    osa_princ_ent_rec           adb;
    kadm5_policy_ent_rec        polent;
    krb5_boolean                have_polent = FALSE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -342,6 +342,20 @@
 
     /* This will make the caller use a random password instead. */
     *passptr = NULL;
+}
+
+/* Return the number of keys with the newest kvno.  Assumes that all key data
+ * with the newest kvno are at the front of the key data array. */
+static int
+count_new_keys(int n_key_data, krb5_key_data *key_data)
+{
+    int n;
+
+    for (n = 1; n < n_key_data; n++) {
+        if (key_data[n - 1].key_data_kvno != key_data[n].key_data_kvno)
+            return n;
+    }
+    return n_key_data;
 }
 
 kadm5_ret_t
@@ -1593,7 +1607,7 @@
     osa_princ_ent_rec           adb;
     krb5_int32                  now;
     kadm5_policy_ent_rec        pol;
-    int                         ret, last_pwd;
+    int                         ret, last_pwd, n_new_keys;
     krb5_boolean                have_pol = FALSE;
     kadm5_server_handle_t       handle = server_handle;
     krb5_keyblock               *act_mkey;
@@ -1686,8 +1700,9 @@
     kdb->fail_auth_count = 0;
 
     if (keyblocks) {
-        ret = decrypt_key_data(handle->context,
-                               kdb->n_key_data, kdb->key_data,
+        /* Return only the new keys added by krb5_dbe_crk. */
+        n_new_keys = count_new_keys(kdb->n_key_data, kdb->key_data);
+        ret = decrypt_key_data(handle->context, n_new_keys, kdb->key_data,
                                keyblocks, n_keys);
         if (ret)
             goto done;
```
