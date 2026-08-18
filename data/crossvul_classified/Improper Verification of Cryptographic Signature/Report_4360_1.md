# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in python
**Pair ID:** 4360_1
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4360_1`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```python
Lines 1-26 of the vulnerable file.

import logging
import os.path
import warnings
from typing import Dict
from typing import Optional

from oic import rndstr
from oic.exception import AuthzError
from oic.exception import MessageException
from oic.exception import NotForMe
from oic.exception import PyoidcError
from oic.oauth2 import Grant
from oic.oauth2.consumer import TokenError
from oic.oauth2.consumer import UnknownState
from oic.oauth2.consumer import stateID
from oic.oauth2.message import ErrorResponse
from oic.oic import ENDPOINTS
from oic.oic import Client
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AuthorizationResponse
from oic.oic.message import BackChannelLogoutRequest
from oic.oic.message import Claims
from oic.oic.message import ClaimsRequest
from oic.utils import http_util
from oic.utils.sanitize import sanitize
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,8 @@
 import warnings
 from typing import Dict
 from typing import Optional
+from typing import Tuple
+from typing import Union
 
 from oic import rndstr
 from oic.exception import AuthzError
@@ -22,6 +24,7 @@
 from oic.oic.message import BackChannelLogoutRequest
 from oic.oic.message import Claims
 from oic.oic.message import ClaimsRequest
+from oic.oic.message import IdToken
 from oic.utils import http_util
 from oic.utils.sanitize import sanitize
 from oic.utils.sdb import DictSessionBackend
@@ -340,6 +343,7 @@
         if self.debug:
             _log_info("Redirecting to: %s" % location)
 
+        self.authz_req[areq["state"]] = areq
         return sid, location
 
     def _parse_authz(self, query="", **kwargs):
@@ -364,7 +368,16 @@
         self.redirect_uris = [self.sdb[_state]["redirect_uris"]]
         return aresp, _state
 
-    def parse_authz(self, query="", **kwargs):
+    def parse_authz(
+        self, query="", **kwargs
+    ) -> Union[
+        http_util.BadRequest,
+        Tuple[
+            Optional[AuthorizationResponse],
+            Optional[AccessTokenResponse],
+            Optional[IdToken],
+        ],
+    ]:
         """
         Parse authorization response from server.
 
@@ -375,17 +388,20 @@
         ["id_token"]
         ["id_token", "token"]
         ["token"]
-
-        :return: A AccessTokenResponse instance
         """
         _log_info = logger.info
         logger.debug("- authorization -")
 
+        # FIXME: This shouldn't be here... We should rather raise a sepcific Client error
+        # That would simplify the return value of this function
+        # and drop bunch of assertions from tests added in this commit.
         if not query:
             return http_util.BadRequest("Missing query")
 
         _log_info("response: %s" % sanitize(query))
 
+        if "algs" not in kwargs:
+            kwargs["algs"] = self.sign_enc_algs("id_token")
         if "code" in self.consumer_config["response_type"]:
             aresp, _state = self._parse_authz(query, **kwargs)
 
@@ -410,9 +426,10 @@
                 except KeyError:
                     pass
 
-            return aresp, atr, idt
         elif "token" in self.consumer_config["response_type"]:  # implicit flow
             _log_info("Expect Access Token Response")
+            aresp = None
+            _state = None
             atr = self.parse_response(
                 AccessTokenResponse,
                 info=query,
@@ -423,8 +440,8 @@
             if isinstance(atr, ErrorResponse):
                 raise TokenError(atr.get("error"), atr)
 
-            idt = None
-            return None, atr, idt
+            idt = atr.get("id_token")
+
         else:  # only id_token
             aresp, _state = self._parse_authz(query, **kwargs)
 
@@ -437,8 +454,13 @@
                     session_update(self.sso_db, _state, "smid", idt["sid"])
                 except KeyError:
                     pass
-
-            return None, None, idt
+            # Null the aresp as only id_token should be returned
+            aresp = atr = None
+
+        # Verify the IdToken if it was present
+        if idt is not None:
+            self.verify_id_token(idt, self.authz_req.get(_state or atr["state"]))
+        return aresp, atr, idt
 
     def complete(self, state):
         """
```
