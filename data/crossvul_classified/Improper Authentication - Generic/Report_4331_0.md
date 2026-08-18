# CrossVul Fix Pair: Improper Authentication in python
**Pair ID:** 4331_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4331_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```python
Lines 9-49 of the vulnerable file.

from alerta.models.permission import Permission
from alerta.models.user import User
from alerta.utils.audit import auth_audit_trail

from . import auth


@auth.route('/auth/login', methods=['OPTIONS', 'POST'])
@cross_origin(supports_credentials=True)
def login():
    # Allow LDAP server to use a self signed certificate
    if current_app.config['LDAP_ALLOW_SELF_SIGNED_CERT']:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)

    # Retrieve required fields from client request
    try:
        login = request.json.get('username', None) or request.json['email']
        password = request.json['password']
    except KeyError:
        raise ApiError("must supply 'username' and 'password'", 401)

    try:
        if '\\' in login:
            domain, username = login.split('\\')
            email = ''
            email_verified = False
        else:
            username, domain = login.split('@')
            email = login
            email_verified = True
    except ValueError:
        raise ApiError('expected username with domain', 401)

    # Validate LDAP domain
    if domain not in current_app.config['LDAP_DOMAINS']:
        raise ApiError('unauthorized domain', 403)

    userdn = current_app.config['LDAP_DOMAINS'][domain] % username

    # Attempt LDAP AUTH
    try:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,9 @@
         password = request.json['password']
     except KeyError:
         raise ApiError("must supply 'username' and 'password'", 401)
+
+    if not password:
+        raise ApiError('password not allowed to be empty', 401)
 
     try:
         if '\\' in login:
```
