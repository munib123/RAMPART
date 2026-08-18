# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 100_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `100_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 1-37 of the vulnerable file.

# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging

from synapse.api.errors import SynapseError
from synapse.crypto.event_signing import check_event_content_hash
from synapse.events import FrozenEvent
from synapse.events.utils import prune_event
from synapse.http.servlet import assert_params_in_request
from synapse.util import unwrapFirstError, logcontext
from twisted.internet import defer

logger = logging.getLogger(__name__)


class FederationBase(object):
    def __init__(self, hs):
        self.hs = hs

        self.server_name = hs.hostname
        self.keyring = hs.get_keyring()
        self.spam_checker = hs.get_spam_checker()
        self.store = hs.get_datastore()
        self._clock = hs.get_clock()

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,10 @@
 # limitations under the License.
 import logging
 
-from synapse.api.errors import SynapseError
+import six
+
+from synapse.api.constants import MAX_DEPTH
+from synapse.api.errors import SynapseError, Codes
 from synapse.crypto.event_signing import check_event_content_hash
 from synapse.events import FrozenEvent
 from synapse.events.utils import prune_event
@@ -190,11 +193,23 @@
         FrozenEvent
 
     Raises:
-        SynapseError: if the pdu is missing required fields
+        SynapseError: if the pdu is missing required fields or is otherwise
+            not a valid matrix event
     """
     # we could probably enforce a bunch of other fields here (room_id, sender,
     # origin, etc etc)
-    assert_params_in_request(pdu_json, ('event_id', 'type'))
+    assert_params_in_request(pdu_json, ('event_id', 'type', 'depth'))
+
+    depth = pdu_json['depth']
+    if not isinstance(depth, six.integer_types):
+        raise SynapseError(400, "Depth %r not an intger" % (depth, ),
+                           Codes.BAD_JSON)
+
+    if depth < 0:
+        raise SynapseError(400, "Depth too small", Codes.BAD_JSON)
+    elif depth > MAX_DEPTH:
+        raise SynapseError(400, "Depth too large", Codes.BAD_JSON)
+
     event = FrozenEvent(
         pdu_json
     )
```
