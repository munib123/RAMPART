# CrossVul Fix Pair: Uncontrolled Resource Consumption in python
**Pair ID:** 4373_3
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4373_3`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```python
Lines 38-78 of the vulnerable file.

    RoomEncryptionAlgorithms,
)
from synapse.api.errors import (
    AuthError,
    CodeMessageException,
    Codes,
    FederationDeniedError,
    FederationError,
    HttpResponseException,
    NotFoundError,
    RequestSendFailed,
    SynapseError,
)
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS, RoomVersion, RoomVersions
from synapse.crypto.event_signing import compute_event_signature
from synapse.event_auth import auth_types_for_event
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.events.validator import EventValidator
from synapse.handlers._base import BaseHandler
from synapse.logging.context import (
    make_deferred_yieldable,
    nested_logging_context,
    preserve_fn,
    run_in_background,
)
from synapse.logging.utils import log_function
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.replication.http.devices import ReplicationUserDevicesResyncRestServlet
from synapse.replication.http.federation import (
    ReplicationCleanRoomRestServlet,
    ReplicationFederationSendEventsRestServlet,
    ReplicationStoreRoomOnInviteRestServlet,
)
from synapse.state import StateResolutionStore
from synapse.storage.databases.main.events_worker import EventRedactBehaviour
from synapse.types import (
    JsonDict,
    MutableStateMap,
    PersistedEventPosition,
    RoomStreamToken,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,6 +55,7 @@
 from synapse.events.snapshot import EventContext
 from synapse.events.validator import EventValidator
 from synapse.handlers._base import BaseHandler
+from synapse.http.servlet import assert_params_in_dict
 from synapse.logging.context import (
     make_deferred_yieldable,
     nested_logging_context,
@@ -2686,7 +2687,7 @@
             )
 
     async def on_exchange_third_party_invite_request(
-        self, room_id: str, event_dict: JsonDict
+        self, event_dict: JsonDict
     ) -> None:
         """Handle an exchange_third_party_invite request from a remote server
 
@@ -2694,12 +2695,11 @@
         into a normal m.room.member invite.
 
         Args:
-            room_id: The ID of the room.
-
-            event_dict (dict[str, Any]): Dictionary containing the event body.
-
-        """
-        room_version = await self.store.get_room_version_id(room_id)
+            event_dict: Dictionary containing the event body.
+
+        """
+        assert_params_in_dict(event_dict, ["room_id"])
+        room_version = await self.store.get_room_version_id(event_dict["room_id"])
 
         # NB: event_dict has a particular specced format we might need to fudge
         # if we change event formats too much.
```
