# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in python
**Pair ID:** 3972_0
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3972_0`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```python
Lines 7-47 of the vulnerable file.

#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from abc import ABC, abstractmethod
import attr
import collections
import enum
import fnmatch
import itertools
import logging
import math
import os
import pathlib
import platform

from curtin import storage_config
from curtin.util import human2bytes

from probert.storage import StorageInfo

log = logging.getLogger('subiquity.models.filesystem')


def _set_backlinks(obj):
    for field in attr.fields(type(obj)):
        backlink = field.metadata.get('backlink')
        if backlink is None:
            continue
        v = getattr(obj, field.name)
        if v is None:
            continue
        if not isinstance(v, (list, set)):
            v = [v]
        for vv in v:
            b = getattr(vv, backlink, None)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,6 +24,7 @@
 import os
 import pathlib
 import platform
+import tempfile
 
 from curtin import storage_config
 from curtin.util import human2bytes
@@ -1178,6 +1179,16 @@
 class DM_Crypt:
     volume = attributes.ref(backlink="_constructed_device")  # _Formattable
     key = attr.ib(metadata={'redact': True})
+
+    def serialize_key(self):
+        if self.key:
+            f = tempfile.NamedTemporaryFile(
+                prefix='luks-key-', mode='w', delete=False)
+            f.write(self.key)
+            f.close()
+            return {'keyfile': f.name}
+        else:
+            return {}
 
     dm_name = attr.ib(default=None)
     preserve = attr.ib(default=False)
```
