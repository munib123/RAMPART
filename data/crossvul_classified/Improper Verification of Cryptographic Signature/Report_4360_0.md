# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in python
**Pair ID:** 4360_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4360_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```python
Lines 27-67 of the vulnerable file.

from oic import rndstr
from oic.exception import AccessDenied
from oic.exception import AuthnToOld
from oic.exception import AuthzError
from oic.exception import CommunicationError
from oic.exception import MissingParameter
from oic.exception import ParameterError
from oic.exception import PyoidcError
from oic.exception import RegistrationError
from oic.exception import RequestError
from oic.exception import SubMismatch
from oic.oauth2 import HTTP_ARGS
from oic.oauth2 import authz_error
from oic.oauth2.consumer import ConfigurationError
from oic.oauth2.exception import MissingRequiredAttribute
from oic.oauth2.exception import OtherError
from oic.oauth2.exception import ParseError
from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import Message
from oic.oauth2.message import MessageFactory
from oic.oauth2.util import get_or_post
from oic.oic.message import SCOPE2CLAIMS
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AuthorizationErrorResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AuthorizationResponse
from oic.oic.message import Claims
from oic.oic.message import ClaimsRequest
from oic.oic.message import ClientRegistrationErrorResponse
from oic.oic.message import EndSessionRequest
from oic.oic.message import IdToken
from oic.oic.message import JasonWebToken
from oic.oic.message import OIDCMessageFactory
from oic.oic.message import OpenIDRequest
from oic.oic.message import OpenIDSchema
from oic.oic.message import RefreshSessionRequest
from oic.oic.message import RegistrationRequest
from oic.oic.message import RegistrationResponse
from oic.oic.message import TokenErrorResponse
from oic.oic.message import UserInfoErrorResponse
from oic.oic.message import UserInfoRequest
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,6 +44,7 @@
 from oic.oauth2.message import ErrorResponse
 from oic.oauth2.message import Message
 from oic.oauth2.message import MessageFactory
+from oic.oauth2.message import WrongSigningAlgorithm
 from oic.oauth2.util import get_or_post
 from oic.oic.message import SCOPE2CLAIMS
 from oic.oic.message import AccessTokenResponse
@@ -1432,7 +1433,13 @@
         return resp
 
     def _verify_id_token(
-        self, id_token, nonce="", acr_values=None, auth_time=0, max_age=0
+        self,
+        id_token,
+        nonce="",
+        acr_values=None,
+        auth_time=0,
+        max_age=0,
+        response_type="",
     ):
         """
         Verify IdToken.
@@ -1465,6 +1472,11 @@
         if _now > id_token["exp"]:
             raise OtherError("Passed best before date")
 
+        if response_type != ["code"] and id_token.jws_header["alg"] == "none":
+            raise WrongSigningAlgorithm(
+                "none is not allowed outside Authorization Flow."
+            )
+
         if (
             self.id_token_max_age
             and _now > int(id_token["iat"]) + self.id_token_max_age
@@ -1491,7 +1503,7 @@
         except KeyError:
             pass
 
-        for param in ["acr_values", "max_age"]:
+        for param in ["acr_values", "max_age", "response_type"]:
             try:
                 kwa[param] = authn_req[param]
             except KeyError:
```
