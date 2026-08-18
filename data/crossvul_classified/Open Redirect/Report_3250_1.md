# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 3250_1
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3250_1`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 1-36 of the vulnerable file.

"""
.. module: security_monkey.sso.views
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Patrick Kelley <patrick@netflix.com>
"""
import jwt
import base64
import requests

from flask import Blueprint, current_app, redirect, request

from flask.ext.restful import reqparse, Resource, Api
from flask.ext.principal import Identity, identity_changed
from flask_login import login_user

try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.utils import OneLogin_Saml2_Utils
    onelogin_import_success = True
except ImportError:
    onelogin_import_success = False

from .service import fetch_token_header_payload, get_rsa_public_key

from security_monkey.datastore import User
from security_monkey import db, rbac

from urlparse import urlparse

mod = Blueprint('sso', __name__)
api = Api(mod)


from flask_security.utils import validate_redirect_url
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,7 @@
 
 from flask.ext.restful import reqparse, Resource, Api
 from flask.ext.principal import Identity, identity_changed
-from flask_login import login_user
+from flask_security.utils import login_user
 
 try:
     from onelogin.saml2.auth import OneLogin_Saml2_Auth
@@ -264,7 +264,7 @@
         auth.process_response()
         errors = auth.get_errors()
         if not errors:
-            if auth.is_authenticated():
+            if auth.is_authenticated:
                 return True
             else:
                 return False
```
