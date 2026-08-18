# CrossVul Fix Pair: Uncontrolled Resource Consumption in python
**Pair ID:** 4373_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4373_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```python
Lines 32-72 of the vulnerable file.

from twisted.internet import defer
from twisted.internet.abstract import isIPAddress
from twisted.python import failure

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import (
    AuthError,
    Codes,
    FederationError,
    IncompatibleRoomVersionError,
    NotFoundError,
    SynapseError,
    UnsupportedRoomVersionError,
)
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events import EventBase
from synapse.federation.federation_base import FederationBase, event_from_pdu_json
from synapse.federation.persistence import TransactionActions
from synapse.federation.units import Edu, Transaction
from synapse.http.endpoint import parse_server_name
from synapse.logging.context import (
    make_deferred_yieldable,
    nested_logging_context,
    run_in_background,
)
from synapse.logging.opentracing import log_kv, start_active_span_from_edu, trace
from synapse.logging.utils import log_function
from synapse.replication.http.federation import (
    ReplicationFederationSendEduRestServlet,
    ReplicationGetQueryRestServlet,
)
from synapse.types import JsonDict, get_domain_from_id
from synapse.util import glob_to_regex, json_decoder, unwrapFirstError
from synapse.util.async_helpers import Linearizer, concurrently_execute
from synapse.util.caches.response_cache import ResponseCache

if TYPE_CHECKING:
    from synapse.server import HomeServer

# when processing incoming transactions, we try to handle multiple rooms in
# parallel, up to this limit.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,6 +49,7 @@
 from synapse.federation.persistence import TransactionActions
 from synapse.federation.units import Edu, Transaction
 from synapse.http.endpoint import parse_server_name
+from synapse.http.servlet import assert_params_in_dict
 from synapse.logging.context import (
     make_deferred_yieldable,
     nested_logging_context,
@@ -391,7 +392,7 @@
             TRANSACTION_CONCURRENCY_LIMIT,
         )
 
-    async def on_context_state_request(
+    async def on_room_state_request(
         self, origin: str, room_id: str, event_id: str
     ) -> Tuple[int, Dict[str, Any]]:
         origin_host, _ = parse_server_name(origin)
@@ -514,11 +515,12 @@
         return {"event": ret_pdu.get_pdu_json(time_now)}
 
     async def on_send_join_request(
-        self, origin: str, content: JsonDict, room_id: str
+        self, origin: str, content: JsonDict
     ) -> Dict[str, Any]:
         logger.debug("on_send_join_request: content: %s", content)
 
-        room_version = await self.store.get_room_version(room_id)
+        assert_params_in_dict(content, ["room_id"])
+        room_version = await self.store.get_room_version(content["room_id"])
         pdu = event_from_pdu_json(content, room_version)
 
         origin_host, _ = parse_server_name(origin)
@@ -547,12 +549,11 @@
         time_now = self._clock.time_msec()
         return {"event": pdu.get_pdu_json(time_now), "room_version": room_version}
 
-    async def on_send_leave_request(
-        self, origin: str, content: JsonDict, room_id: str
-    ) -> dict:
+    async def on_send_leave_request(self, origin: str, content: JsonDict) -> dict:
         logger.debug("on_send_leave_request: content: %s", content)
 
-        room_version = await self.store.get_room_version(room_id)
+        assert_params_in_dict(content, ["room_id"])
+        room_version = await self.store.get_room_version(content["room_id"])
         pdu = event_from_pdu_json(content, room_version)
 
         origin_host, _ = parse_server_name(origin)
@@ -748,12 +749,8 @@
         )
         return ret
 
-    async def on_exchange_third_party_invite_request(
-        self, room_id: str, event_dict: Dict
-    ):
-        ret = await self.handler.on_exchange_third_party_invite_request(
-            room_id, event_dict
-        )
+    async def on_exchange_third_party_invite_request(self, event_dict: Dict):
+        ret = await self.handler.on_exchange_third_party_invite_request(event_dict)
         return ret
 
     async def check_server_matches_acl(self, server_name: str, room_id: str):
```
