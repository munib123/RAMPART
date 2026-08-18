# CrossVul Fix Pair: Improper Certificate Validation in c
**Pair ID:** 3203_1
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3203_1`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```c
Lines 638-678 of the vulnerable file.

	kdc_log(context, config, 0,
		"Transited type 0 with non empty content");
	return KRB5KDC_ERR_TRTYPE_NOSUPP;
    default:
	kdc_log(context, config, 0,
		"Unknown transited type: %u", tr->tr_type);
	return KRB5KDC_ERR_TRTYPE_NOSUPP;
    }

    ret = krb5_domain_x500_decode(context,
				  tr->contents,
				  &realms,
				  &num_realms,
				  client_realm,
				  server_realm);
    if(ret){
	krb5_warn(context, ret,
		  "Decoding transited encoding");
	return ret;
    }
    if(strcmp(client_realm, tgt_realm) && strcmp(server_realm, tgt_realm)) {
	/* not us, so add the previous realm to transited set */
	if (num_realms + 1 > UINT_MAX/sizeof(*realms)) {
	    ret = ERANGE;
	    goto free_realms;
	}
	tmp = realloc(realms, (num_realms + 1) * sizeof(*realms));
	if(tmp == NULL){
	    ret = ENOMEM;
	    goto free_realms;
	}
	realms = tmp;
	realms[num_realms] = strdup(tgt_realm);
	if(realms[num_realms] == NULL){
	    ret = ENOMEM;
	    goto free_realms;
	}
	num_realms++;
    }
    if(num_realms == 0) {
	if(strcmp(client_realm, server_realm))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -655,8 +655,12 @@
 		  "Decoding transited encoding");
 	return ret;
     }
+
+    /*
+     * If the realm of the presented tgt is neither the client nor the server
+     * realm, it is a transit realm and must be added to transited set.
+     */
     if(strcmp(client_realm, tgt_realm) && strcmp(server_realm, tgt_realm)) {
-	/* not us, so add the previous realm to transited set */
 	if (num_realms + 1 > UINT_MAX/sizeof(*realms)) {
 	    ret = ERANGE;
 	    goto free_realms;
@@ -737,6 +741,7 @@
 	       const char *server_name,
 	       hdb_entry_ex *client,
 	       krb5_principal client_principal,
+               const char *tgt_realm,
 	       hdb_entry_ex *krbtgt,
 	       krb5_enctype krbtgt_etype,
 	       krb5_principals spp,
@@ -798,7 +803,7 @@
 				 &tgt->transited, &et,
 				 krb5_principal_get_realm(context, client_principal),
 				 krb5_principal_get_realm(context, server->entry.principal),
-				 krb5_principal_get_realm(context, krbtgt->entry.principal));
+				 tgt_realm);
     if(ret)
 	goto out;
 
@@ -1519,6 +1524,8 @@
     krb5_keyblock sessionkey;
     krb5_kvno kvno;
     krb5_data rspac;
+    const char *tgt_realm = /* Realm of TGT issuer */
+        krb5_principal_get_realm(context, krbtgt->entry.principal);
     const char *our_realm = /* Realm of this KDC */
         krb5_principal_get_comp_string(context, krbtgt->entry.principal, 1);
     char **capath = NULL;
@@ -2324,6 +2331,7 @@
 			 spn,
 			 client,
 			 cp,
+                         tgt_realm,
 			 krbtgt_out,
 			 tkey_sign->key.keytype,
 			 spp,
```
