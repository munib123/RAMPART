# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 3683_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3683_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 8-49 of the vulnerable file.

#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import netaddr

from nova.compute import api as compute
from nova.scheduler import filters


class AffinityFilter(filters.BaseHostFilter):
    def __init__(self):
        self.compute_api = compute.API()

    def _affinity_host(self, context, instance_id):
        return self.compute_api.get(context, instance_id)['host']


class DifferentHostFilter(AffinityFilter):
    '''Schedule the instance on a different host from a set of instances.'''

    def host_passes(self, host_state, filter_properties):
        context = filter_properties['context']
        scheduler_hints = filter_properties.get('scheduler_hints') or {}
        me = host_state.host

        affinity_uuids = scheduler_hints.get('different_host', [])
        if isinstance(affinity_uuids, basestring):
            affinity_uuids = [affinity_uuids]
        if affinity_uuids:
            return not any([i for i in affinity_uuids
                              if self._affinity_host(context, i) == me])
        # With no different_host key
        return True


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,8 +25,11 @@
     def __init__(self):
         self.compute_api = compute.API()
 
-    def _affinity_host(self, context, instance_id):
-        return self.compute_api.get(context, instance_id)['host']
+    def _all_hosts(self, context):
+        all_hosts = {}
+        for instance in self.compute_api.get_all(context):
+            all_hosts[instance['uuid']] = instance['host']
+        return all_hosts
 
 
 class DifferentHostFilter(AffinityFilter):
@@ -41,8 +44,9 @@
         if isinstance(affinity_uuids, basestring):
             affinity_uuids = [affinity_uuids]
         if affinity_uuids:
+            all_hosts = self._all_hosts(context)
             return not any([i for i in affinity_uuids
-                              if self._affinity_host(context, i) == me])
+                              if all_hosts.get(i) == me])
         # With no different_host key
         return True
 
@@ -61,9 +65,10 @@
         if isinstance(affinity_uuids, basestring):
             affinity_uuids = [affinity_uuids]
         if affinity_uuids:
+            all_hosts = self._all_hosts(context)
             return any([i for i
                           in affinity_uuids
-                          if self._affinity_host(context, i) == me])
+                          if all_hosts.get(i) == me])
         # With no same_host key
         return True
 
```
