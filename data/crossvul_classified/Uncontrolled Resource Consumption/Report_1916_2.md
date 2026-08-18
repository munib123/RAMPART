# CrossVul Fix Pair: Uncontrolled Resource Consumption in python
**Pair ID:** 1916_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1916_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```python
Lines 1-38 of the vulnerable file.

# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import random
import time
from typing import Callable, Dict, Optional, Tuple

import attr

from twisted.internet import defer
from twisted.internet.interfaces import IReactorTime
from twisted.web.client import RedirectAgent, readBody
from twisted.web.http import stringToDatetime
from twisted.web.http_headers import Headers
from twisted.web.iweb import IAgent, IResponse

from synapse.logging.context import make_deferred_yieldable
from synapse.util import Clock, json_decoder
from synapse.util.caches.ttlcache import TTLCache
from synapse.util.metrics import Measure

# period to cache .well-known results for by default
WELL_KNOWN_DEFAULT_CACHE_PERIOD = 24 * 3600

# jitter factor to add to the .well-known default cache ttls
WELL_KNOWN_DEFAULT_CACHE_PERIOD_JITTER = 0.1
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,17 +15,19 @@
 import logging
 import random
 import time
+from io import BytesIO
 from typing import Callable, Dict, Optional, Tuple
 
 import attr
 
 from twisted.internet import defer
 from twisted.internet.interfaces import IReactorTime
-from twisted.web.client import RedirectAgent, readBody
+from twisted.web.client import RedirectAgent
 from twisted.web.http import stringToDatetime
 from twisted.web.http_headers import Headers
 from twisted.web.iweb import IAgent, IResponse
 
+from synapse.http.client import BodyExceededMaxSize, read_body_with_max_size
 from synapse.logging.context import make_deferred_yieldable
 from synapse.util import Clock, json_decoder
 from synapse.util.caches.ttlcache import TTLCache
@@ -52,6 +54,9 @@
 
 # lower bound for .well-known cache period
 WELL_KNOWN_MIN_CACHE_PERIOD = 5 * 60
+
+# The maximum size (in bytes) to allow a well-known file to be.
+WELL_KNOWN_MAX_SIZE = 50 * 1024  # 50 KiB
 
 # Attempt to refetch a cached well-known N% of the TTL before it expires.
 # e.g. if set to 0.2 and we have a cached entry with a TTL of 5mins, then
@@ -229,6 +234,9 @@
             server_name: name of the server, from the requested url
             retry: Whether to retry the request if it fails.
 
+        Raises:
+            _FetchWellKnownFailure if we fail to lookup a result
+
         Returns:
             Returns the response object and body. Response may be a non-200 response.
         """
@@ -250,7 +258,11 @@
                         b"GET", uri, headers=Headers(headers)
                     )
                 )
-                body = await make_deferred_yieldable(readBody(response))
+                body_stream = BytesIO()
+                await make_deferred_yieldable(
+                    read_body_with_max_size(response, body_stream, WELL_KNOWN_MAX_SIZE)
+                )
+                body = body_stream.getvalue()
 
                 if 500 <= response.code < 600:
                     raise Exception("Non-200 response %s" % (response.code,))
@@ -259,6 +271,15 @@
             except defer.CancelledError:
                 # Bail if we've been cancelled
                 raise
+            except BodyExceededMaxSize:
+                # If the well-known file was too large, do not keep attempting
+                # to download it, but consider it a temporary error.
+                logger.warning(
+                    "Requested .well-known file for %s is too large > %r bytes",
+                    server_name.decode("ascii"),
+                    WELL_KNOWN_MAX_SIZE,
+                )
+                raise _FetchWellKnownFailure(temporary=True)
             except Exception as e:
                 if not retry or i >= WELL_KNOWN_RETRY_ATTEMPTS:
                     logger.info("Error fetching %s: %s", uri_str, e)
```
