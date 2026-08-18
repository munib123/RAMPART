# CrossVul Fix Pair: Uncontrolled Resource Consumption in python
**Pair ID:** 1916_3
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1916_3`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```python
Lines 20-60 of the vulnerable file.

import urllib.parse
from io import BytesIO
from typing import Callable, Dict, List, Optional, Tuple, Union

import attr
import treq
from canonicaljson import encode_canonical_json
from prometheus_client import Counter
from signedjson.sign import sign_json

from twisted.internet import defer
from twisted.internet.error import DNSLookupError
from twisted.internet.interfaces import IReactorTime
from twisted.internet.task import _EPSILON, Cooperator
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer, IResponse

import synapse.metrics
import synapse.util.retryutils
from synapse.api.errors import (
    FederationDeniedError,
    HttpResponseException,
    RequestSendFailed,
)
from synapse.http import QuieterFileBodyProducer
from synapse.http.client import (
    BlacklistingAgentWrapper,
    BlacklistingReactorWrapper,
    encode_query_args,
    readBodyToFile,
)
from synapse.http.federation.matrix_federation_agent import MatrixFederationAgent
from synapse.logging.context import make_deferred_yieldable
from synapse.logging.opentracing import (
    inject_active_span_byte_dict,
    set_tag,
    start_active_span,
    tags,
)
from synapse.types import JsonDict
from synapse.util import json_decoder
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,16 +37,19 @@
 import synapse.metrics
 import synapse.util.retryutils
 from synapse.api.errors import (
+    Codes,
     FederationDeniedError,
     HttpResponseException,
     RequestSendFailed,
+    SynapseError,
 )
 from synapse.http import QuieterFileBodyProducer
 from synapse.http.client import (
     BlacklistingAgentWrapper,
     BlacklistingReactorWrapper,
+    BodyExceededMaxSize,
     encode_query_args,
-    readBodyToFile,
+    read_body_with_max_size,
 )
 from synapse.http.federation.matrix_federation_agent import MatrixFederationAgent
 from synapse.logging.context import make_deferred_yieldable
@@ -975,9 +978,15 @@
         headers = dict(response.headers.getAllRawHeaders())
 
         try:
-            d = readBodyToFile(response, output_stream, max_size)
+            d = read_body_with_max_size(response, output_stream, max_size)
             d.addTimeout(self.default_timeout, self.reactor)
             length = await make_deferred_yieldable(d)
+        except BodyExceededMaxSize:
+            msg = "Requested file is too large > %r bytes" % (max_size,)
+            logger.warning(
+                "{%s} [%s] %s", request.txn_id, request.destination, msg,
+            )
+            SynapseError(502, msg, Codes.TOO_LARGE)
         except Exception as e:
             logger.warning(
                 "{%s} [%s] Error reading response: %s",
```
