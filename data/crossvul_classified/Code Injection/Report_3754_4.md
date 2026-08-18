# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in python
**Pair ID:** 3754_4
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3754_4`)

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

import os
from ConfigParser import ConfigParser, NoSectionError, NoOptionError

from swift.common.memcached import MemcacheRing


class MemcacheMiddleware(object):
    """
    Caching middleware that manages caching in swift.
    """

    def __init__(self, app, conf):
        self.app = app
        self.memcache_servers = conf.get('memcache_servers')
        if not self.memcache_servers:
            path = os.path.join(conf.get('swift_dir', '/etc/swift'),
                                'memcache.conf')
            memcache_conf = ConfigParser()
            if memcache_conf.read(path):
                try:
                    self.memcache_servers = \
                        memcache_conf.get('memcache', 'memcache_servers')
                except (NoSectionError, NoOptionError):
                    pass
        if not self.memcache_servers:
            self.memcache_servers = '127.0.0.1:11211'
        self.memcache = MemcacheRing(
            [s.strip() for s in self.memcache_servers.split(',') if s.strip()])

    def __call__(self, env, start_response):
        env['swift.cache'] = self.memcache
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,20 +27,36 @@
     def __init__(self, app, conf):
         self.app = app
         self.memcache_servers = conf.get('memcache_servers')
-        if not self.memcache_servers:
+        serialization_format = conf.get('memcache_serialization_support')
+
+        if not self.memcache_servers or serialization_format is None:
             path = os.path.join(conf.get('swift_dir', '/etc/swift'),
                                 'memcache.conf')
             memcache_conf = ConfigParser()
             if memcache_conf.read(path):
-                try:
-                    self.memcache_servers = \
-                        memcache_conf.get('memcache', 'memcache_servers')
-                except (NoSectionError, NoOptionError):
-                    pass
+                if not self.memcache_servers:
+                    try:
+                        self.memcache_servers = \
+                            memcache_conf.get('memcache', 'memcache_servers')
+                    except (NoSectionError, NoOptionError):
+                        pass
+                if serialization_format is None:
+                    try:
+                        serialization_format = \
+                            memcache_conf.get('memcache',
+                                              'memcache_serialization_support')
+                    except (NoSectionError, NoOptionError):
+                        pass
+
         if not self.memcache_servers:
             self.memcache_servers = '127.0.0.1:11211'
+        if serialization_format is None:
+            serialization_format = 2
+
         self.memcache = MemcacheRing(
-            [s.strip() for s in self.memcache_servers.split(',') if s.strip()])
+            [s.strip() for s in self.memcache_servers.split(',') if s.strip()],
+            allow_pickle=(serialization_format == 0),
+            allow_unpickle=(serialization_format <= 1))
 
     def __call__(self, env, start_response):
         env['swift.cache'] = self.memcache
```
