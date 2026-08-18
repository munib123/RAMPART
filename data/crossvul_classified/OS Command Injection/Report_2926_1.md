# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in python
**Pair ID:** 2926_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2926_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```python
Lines 2-42 of the vulnerable file.

#    Copyright (C) 2008-2017 Oprea Dan, Bart de Koning, Richard Bailey, Germar Reitze
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


import os
import pluginmanager
import gettext

_=gettext.gettext


class NotifyPlugin( pluginmanager.Plugin ):
    def __init__( self ):
        self.user = ''

        try:
            self.user = os.getlogin()
        except:
            pass

        if not self.user:
            try:
                user = os.environ['USER']
            except:
                pass

        if not self.user:
            try:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
 import os
 import pluginmanager
 import gettext
+import subprocess
 
 _=gettext.gettext
 
@@ -64,15 +65,15 @@
 
     def on_message( self, profile_id, profile_name, level, message, timeout ):
         if 1 == level:
-            cmd = "notify-send "
+            cmd = ['notify-send']
             if timeout > 0:
-                cmd = cmd + " -t %s" % (1000 * timeout)
+                cmd.extend(['-t', str(1000 * timeout)])
 
             title = "Back In Time (%s) : %s" % (self.user, profile_name)
             message = message.replace("\n", ' ')
             message = message.replace("\r", '')
 
-            cmd = cmd + " \"%s\" \"%s\"" % (title, message)
-            print(cmd)
-            os.system(cmd)
+            cmd.append(title)
+            cmd.append(message)
+            subprocess.Popen(cmd).communicate()
         return
```
