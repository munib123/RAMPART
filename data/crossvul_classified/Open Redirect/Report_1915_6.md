# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 1915_6
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1915_6`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 18-58 of the vulnerable file.

import urllib
from typing import Any, Dict, Optional

from synapse.api.constants import Membership
from synapse.api.errors import Codes, HttpResponseException, SynapseError
from synapse.api.urls import (
    FEDERATION_UNSTABLE_PREFIX,
    FEDERATION_V1_PREFIX,
    FEDERATION_V2_PREFIX,
)
from synapse.logging.utils import log_function

logger = logging.getLogger(__name__)


class TransportLayerClient:
    """Sends federation HTTP requests to other servers"""

    def __init__(self, hs):
        self.server_name = hs.hostname
        self.client = hs.get_http_client()

    @log_function
    def get_room_state_ids(self, destination, room_id, event_id):
        """ Requests all state for a given room from the given server at the
        given event. Returns the state's event_id's

        Args:
            destination (str): The host name of the remote homeserver we want
                to get the state from.
            context (str): The name of the context we want the state of
            event_id (str): The event we want the context at.

        Returns:
            Awaitable: Results in a dict received from the remote homeserver.
        """
        logger.debug("get_room_state_ids dest=%s, room=%s", destination, room_id)

        path = _create_v1_path("/state_ids/%s", room_id)
        return self.client.get_json(
            destination,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,7 +35,7 @@
 
     def __init__(self, hs):
         self.server_name = hs.hostname
-        self.client = hs.get_http_client()
+        self.client = hs.get_federation_http_client()
 
     @log_function
     def get_room_state_ids(self, destination, room_id, event_id):
```
