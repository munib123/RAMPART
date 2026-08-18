# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 2222_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2222_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 318-358 of the vulnerable file.

	return ret_ok;
}


ret_t
cherokee_validator_ldap_check (cherokee_validator_ldap_t *ldap,
                               cherokee_connection_t     *conn)
{
	int                              re;
	ret_t                            ret;
	size_t                           size;
	char                            *dn;
	LDAPMessage                     *message;
	LDAPMessage                     *first;
	char                            *attrs[] = { LDAP_NO_ATTRS, NULL };
	cherokee_validator_ldap_props_t *props   = VAL_LDAP_PROP(ldap);

	/* Sanity checks
	 */
	if ((conn->validator == NULL) ||
	    cherokee_buffer_is_empty (&conn->validator->user))
		return ret_error;

	size = cherokee_buffer_cnt_cspn (&conn->validator->user, 0, "*()");
	if (size != conn->validator->user.len)
		return ret_error;

	/* Build filter
	 */
	ret = init_filter (ldap, props, conn);
	if (ret != ret_ok)
		return ret;

	/* Search
	 */
	re = ldap_search_s (ldap->conn, props->basedn.buf, LDAP_SCOPE_SUBTREE, ldap->filter.buf, attrs, 0, &message);
	if (re != LDAP_SUCCESS) {
		LOG_ERROR (CHEROKEE_ERROR_VALIDATOR_LDAP_SEARCH,
		           props->filter.buf ? props->filter.buf : "");
		return ret_error;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -335,7 +335,8 @@
 	/* Sanity checks
 	 */
 	if ((conn->validator == NULL) ||
-	    cherokee_buffer_is_empty (&conn->validator->user))
+	    cherokee_buffer_is_empty (&conn->validator->user) ||
+	    cherokee_buffer_is_empty (&conn->validator->passwd))
 		return ret_error;
 
 	size = cherokee_buffer_cnt_cspn (&conn->validator->user, 0, "*()");
```
