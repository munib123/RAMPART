# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 1915_8
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1915_8`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 29-69 of the vulnerable file.

)
from synapse.config.emailconfig import ThreepidBehaviour
from synapse.http import RequestTimedOutError
from synapse.http.client import SimpleHttpClient
from synapse.types import JsonDict, Requester
from synapse.util import json_decoder
from synapse.util.hash import sha256_and_url_safe_base64
from synapse.util.stringutils import assert_valid_client_secret, random_string

from ._base import BaseHandler

logger = logging.getLogger(__name__)

id_server_scheme = "https://"


class IdentityHandler(BaseHandler):
    def __init__(self, hs):
        super().__init__(hs)

        self.http_client = SimpleHttpClient(hs)
        # We create a blacklisting instance of SimpleHttpClient for contacting identity
        # servers specified by clients
        self.blacklisting_http_client = SimpleHttpClient(
            hs, ip_blacklist=hs.config.federation_ip_range_blacklist
        )
        self.federation_http_client = hs.get_http_client()
        self.hs = hs

    async def threepid_from_creds(
        self, id_server: str, creds: Dict[str, str]
    ) -> Optional[JsonDict]:
        """
        Retrieve and validate a threepid identifier from a "credentials" dictionary against a
        given identity server

        Args:
            id_server: The identity server to validate 3PIDs against. Must be a
                complete URL including the protocol (http(s)://)
            creds: Dictionary containing the following keys:
                * client_secret|clientSecret: A unique secret str provided by the client
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,13 +46,13 @@
     def __init__(self, hs):
         super().__init__(hs)
 
+        # An HTTP client for contacting trusted URLs.
         self.http_client = SimpleHttpClient(hs)
-        # We create a blacklisting instance of SimpleHttpClient for contacting identity
-        # servers specified by clients
+        # An HTTP client for contacting identity servers specified by clients.
         self.blacklisting_http_client = SimpleHttpClient(
             hs, ip_blacklist=hs.config.federation_ip_range_blacklist
         )
-        self.federation_http_client = hs.get_http_client()
+        self.federation_http_client = hs.get_federation_http_client()
         self.hs = hs
 
     async def threepid_from_creds(
```
