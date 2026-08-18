# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in python
**Pair ID:** 3754_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3754_3`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```python
Lines 10-50 of the vulnerable file.

# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Lucid comes with memcached: v1.4.2.  Protocol documentation for that
version is at:

http://github.com/memcached/memcached/blob/1.4.2/doc/protocol.txt
"""

import cPickle as pickle
import logging
import socket
import time
from bisect import bisect
from hashlib import md5

DEFAULT_MEMCACHED_PORT = 11211

CONN_TIMEOUT = 0.3
IO_TIMEOUT = 2.0
PICKLE_FLAG = 1
NODE_WEIGHT = 50
PICKLE_PROTOCOL = 2
TRY_COUNT = 3

# if ERROR_LIMIT_COUNT errors occur in ERROR_LIMIT_TIME seconds, the server
# will be considered failed for ERROR_LIMIT_DURATION seconds.
ERROR_LIMIT_COUNT = 10
ERROR_LIMIT_TIME = 60
ERROR_LIMIT_DURATION = 60


def md5hash(key):
    return md5(key).hexdigest()


class MemcacheConnectionError(Exception):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,11 +27,17 @@
 from bisect import bisect
 from hashlib import md5
 
+try:
+    import simplejson as json
+except ImportError:
+    import json
+
 DEFAULT_MEMCACHED_PORT = 11211
 
 CONN_TIMEOUT = 0.3
 IO_TIMEOUT = 2.0
 PICKLE_FLAG = 1
+JSON_FLAG = 2
 NODE_WEIGHT = 50
 PICKLE_PROTOCOL = 2
 TRY_COUNT = 3
@@ -57,7 +63,8 @@
     """
 
     def __init__(self, servers, connect_timeout=CONN_TIMEOUT,
-                 io_timeout=IO_TIMEOUT, tries=TRY_COUNT):
+                 io_timeout=IO_TIMEOUT, tries=TRY_COUNT,
+                 allow_pickle=False, allow_unpickle=False):
         self._ring = {}
         self._errors = dict(((serv, []) for serv in servers))
         self._error_limited = dict(((serv, 0) for serv in servers))
@@ -69,6 +76,8 @@
         self._client_cache = dict(((server, []) for server in servers))
         self._connect_timeout = connect_timeout
         self._io_timeout = io_timeout
+        self._allow_pickle = allow_pickle
+        self._allow_unpickle = allow_unpickle or allow_pickle
 
     def _exception_occurred(self, server, e, action='talking'):
         if isinstance(e, socket.timeout):
@@ -130,16 +139,21 @@
 
         :param key: key
         :param value: value
-        :param serialize: if True, value is pickled before sending to memcache
+        :param serialize: if True, value is serialized with JSON before sending
+                          to memcache, or with pickle if configured to use
+                          pickle instead of JSON (to avoid cache poisoning)
         :param timeout: ttl in memcache
         """
         key = md5hash(key)
         if timeout > 0:
             timeout += time.time()
         flags = 0
-        if serialize:
+        if serialize and self._allow_pickle:
             value = pickle.dumps(value, PICKLE_PROTOCOL)
             flags |= PICKLE_FLAG
+        elif serialize:
+            value = json.dumps(value)
+            flags |= JSON_FLAG
         for (server, fp, sock) in self._get_conns(key):
             try:
                 sock.sendall('set %s %d %d %s noreply\r\n%s\r\n' % \
@@ -151,8 +165,9 @@
 
     def get(self, key):
         """
-        Gets the object specified by key.  It will also unpickle the object
-        before returning if it is pickled in memcache.
+        Gets the object specified by key.  It will also unserialize the object
+        before returning if it is serialized in memcache with JSON, or if it
+        is pickled and unpickling is allowed.
 
         :param key: key
         :returns: value of the key in memcache
@@ -168,7 +183,12 @@
                         size = int(line[3])
                         value = fp.read(size)
                         if int(line[2]) & PICKLE_FLAG:
-                            value = pickle.loads(value)
+                            if self._allow_unpickle:
+                                value = pickle.loads(value)
+                            else:
+                                value = None
+                        elif int(line[2]) & JSON_FLAG:
+                            value = json.loads(value)
                         fp.readline()
                     line = fp.readline().strip().split()
                 self._return_conn(server, fp, sock)
@@ -258,7 +278,9 @@
         :param mapping: dictonary of keys and values to be set in memcache
         :param servery_key: key to use in determining which server in the ring
                             is used
-        :param serialize: if True, value is pickled before sending to memcache
+        :param serialize: if True, value is serialized with JSON before sending
+                          to memcache, or with pickle if configured to use
+                          pickle instead of JSON (to avoid cache poisoning)
         :param timeout: ttl for memcache
         """
         server_key = md5hash(server_key)
@@ -268,9 +290,12 @@
         for key, value in mapping.iteritems():
             key = md5hash(key)
             flags = 0
-            if serialize:
+            if serialize and self._allow_pickle:
                 value = pickle.dumps(value, PICKLE_PROTOCOL)
                 flags |= PICKLE_FLAG
+            elif serialize:
+                value = json.dumps(value)
+                flags |= JSON_FLAG
             msg += ('set %s %d %d %s noreply\r\n%s\r\n' %
                     (key, flags, timeout, len(value), value))
         for (server, fp, sock) in self._get_conns(server_key):
@@ -302,7 +327,12 @@
                         size = int(line[3])
                         value = fp.read(size)
                         if int(line[2]) & PICKLE_FLAG:
-                            value = pickle.loads(value)
+                            if self._allow_unpickle:
+                                value = pickle.loads(value)
+                            else:
+                                value = None
+                        elif int(line[2]) & JSON_FLAG:
+                            value = json.loads(value)
                         responses[line[1]] = value
                         fp.readline()
                     line = fp.readline().strip().split()
```
