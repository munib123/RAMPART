# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 100_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `100_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 1-39 of the vulnerable file.

# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
# Copyright 2017 - 2018 New Vector Ltd
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
from twisted.internet import defer, reactor
from twisted.python.failure import Failure

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import AuthError, Codes, SynapseError
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.events.utils import serialize_event
from synapse.events.validator import EventValidator
from synapse.types import (
    UserID, RoomAlias, RoomStreamToken,
)
from synapse.util.async import run_on_reactor, ReadWriteLock, Limiter
from synapse.util.logcontext import preserve_fn, run_in_background
from synapse.util.metrics import measure_func
from synapse.util.frozenutils import frozendict_json_encoder
from synapse.util.stringutils import random_string
from synapse.visibility import filter_events_for_client
from synapse.replication.http.send_event import send_event_to_master

from ._base import BaseHandler

from canonicaljson import encode_canonical_json

import logging
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,7 +16,7 @@
 from twisted.internet import defer, reactor
 from twisted.python.failure import Failure
 
-from synapse.api.constants import EventTypes, Membership
+from synapse.api.constants import EventTypes, Membership, MAX_DEPTH
 from synapse.api.errors import AuthError, Codes, SynapseError
 from synapse.crypto.event_signing import add_hashes_and_signatures
 from synapse.events.utils import serialize_event
@@ -624,6 +624,10 @@
 
         if prev_events_and_hashes:
             depth = max([d for _, _, d in prev_events_and_hashes]) + 1
+            # we cap depth of generated events, to ensure that they are not
+            # rejected by other servers (and so that they can be persisted in
+            # the db)
+            depth = min(depth, MAX_DEPTH)
         else:
             depth = 1
 
```
