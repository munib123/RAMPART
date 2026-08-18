# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in python
**Pair ID:** 5044_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5044_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```python
Lines 6-46 of the vulnerable file.

# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

import gettext
translation=gettext.translation('setroubleshoot-plugins', fallback=True)
_=translation.gettext

from setroubleshoot.util import *
from setroubleshoot.Plugin import Plugin

import commands
import sys

def is_execstack(path):
    if path[0] != "/":
        return False

    x = commands.getoutput("execstack -q %s" % path).split()
    return ( x[0]  == "X" )

def find_execstack(exe, pid):
    execstacklist = []
    for path in commands.getoutput("ldd %s" % exe).split():
        if is_execstack(path) and path not in execstacklist:
                execstacklist.append(path)
    try:
        fd = open("/proc/%s/maps" % pid , "r")
        for rec in fd.readlines():
            for path in rec.split():
                if is_execstack(path) and path not in execstacklist:
                    execstacklist.append(path)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,19 +23,19 @@
 from setroubleshoot.util import *
 from setroubleshoot.Plugin import Plugin
 
-import commands
+import subprocess
 import sys
 
 def is_execstack(path):
     if path[0] != "/":
         return False
 
-    x = commands.getoutput("execstack -q %s" % path).split()
-    return ( x[0]  == "X" )
+    x = subprocess.check_output(["execstack",  "-q", path], universal_newlines=True).split()
+    return ( x[0] == "X" )
 
 def find_execstack(exe, pid):
     execstacklist = []
-    for path in commands.getoutput("ldd %s" % exe).split():
+    for path in subprocess.check_output(["ldd", exe], universal_newlines=True).split():
         if is_execstack(path) and path not in execstacklist:
                 execstacklist.append(path)
     try:
```
