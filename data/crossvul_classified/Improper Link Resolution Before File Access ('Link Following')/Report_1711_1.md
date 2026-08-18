# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in python
**Pair ID:** 1711_1
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1711_1`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```python
Lines 1-25 of the vulnerable file.

# Based on local.py (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
# and chroot.py     (c) 2013, Maykel Moya <mmoya@speedyrails.com>
# and jail.py       (c) 2013, Michael Scherer <misc@zarb.org>
# (c) 2015, Dagobert Michelsen <dam@baltic-online.de>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import distutils.spawn
import traceback
import os
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,6 +2,7 @@
 # and chroot.py     (c) 2013, Maykel Moya <mmoya@speedyrails.com>
 # and jail.py       (c) 2013, Michael Scherer <misc@zarb.org>
 # (c) 2015, Dagobert Michelsen <dam@baltic-online.de>
+# (c) 2015, Toshio Kuratomi <tkuratomi@ansible.com>
 #
 # This file is part of Ansible
 #
@@ -23,12 +24,12 @@
 import distutils.spawn
 import traceback
 import os
-import shutil
 import subprocess
-from subprocess import Popen,PIPE
 from ansible import errors
 from ansible.callbacks import vvv
 import ansible.constants as C
+
+BUFSIZE = 4096
 
 class Connection(object):
     ''' Local zone based connections '''
@@ -44,7 +45,7 @@
                              cwd=self.runner.basedir,
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
-        #stdout, stderr = p.communicate()
+
         zones = []
         for l in pipe.stdout.readlines():
           # 1:work:running:/zones/work:3126dc59-9a07-4829-cde9-a816e4c5040e:native:shared
@@ -97,13 +98,20 @@
     # a modifier
     def _generate_cmd(self, executable, cmd):
         if executable:
+            ### TODO: Why was "-c" removed from here? (vs jail.py)
             local_cmd = [self.zlogin_cmd, self.zone, executable, cmd]
         else:
             local_cmd = '%s "%s" %s' % (self.zlogin_cmd, self.zone, cmd)
         return local_cmd
 
-    def exec_command(self, cmd, tmp_path, become_user=None, sudoable=False, executable=None, in_data=None):
-        ''' run a command on the zone '''
+    def _buffered_exec_command(self, cmd, tmp_path, become_user=None, sudoable=False, executable=None, in_data=None, stdin=subprocess.PIPE):
+        ''' run a command on the zone.  This is only needed for implementing
+        put_file() get_file() so that we don't have to read the whole file
+        into memory.
+
+        compared to exec_command() it looses some niceties like being able to
+        return the process's exit code immediately.
+        '''
 
         if sudoable and self.runner.become and self.runner.become_method not in self.become_methods_supported:
             raise errors.AnsibleError("Internal Error: this module does not support running commands via %s" % self.runner.become_method)
@@ -112,52 +120,61 @@
             raise errors.AnsibleError("Internal Error: this module does not support optimized module pipelining")
 
         # We happily ignore privilege escalation
-        if executable == '/bin/sh':
-          executable = None
         local_cmd = self._generate_cmd(executable, cmd)
 
         vvv("EXEC %s" % (local_cmd), host=self.zone)
         p = subprocess.Popen(local_cmd, shell=isinstance(local_cmd, basestring),
                              cwd=self.runner.basedir,
-                             stdin=subprocess.PIPE,
+                             stdin=stdin,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
+
+        return p
+
+    def exec_command(self, cmd, tmp_path, become_user=None, sudoable=False, executable=None, in_data=None):
+        ''' run a command on the zone '''
+
+        ### TODO: Why all the precautions not to specify /bin/sh? (vs jail.py)
+        if executable == '/bin/sh':
+          executable = None
+
+        p = self._buffered_exec_command(cmd, tmp_path, become_user, sudoable, executable, in_data)
 
         stdout, stderr = p.communicate()
         return (p.returncode, '', stdout, stderr)
 
-    def _normalize_path(self, path, prefix):
-        if not path.startswith(os.path.sep):
-            path = os.path.join(os.path.sep, path)
-        normpath = os.path.normpath(path)
-        return os.path.join(prefix, normpath[1:])
-
-    def _copy_file(self, in_path, out_path):
-        if not os.path.exists(in_path):
-            raise errors.AnsibleFileNotFound("file or module does not exist: %s" % in_path)
-        try:
-            shutil.copyfile(in_path, out_path)
-        except shutil.Error:
-            traceback.print_exc()
-            raise errors.AnsibleError("failed to copy: %s and %s are the same" % (in_path, out_path))
-        except IOError:
-            traceback.print_exc()
-            raise errors.AnsibleError("failed to transfer file to %s" % out_path)
-
     def put_file(self, in_path, out_path):
         ''' transfer a file from local to zone '''
 
-        out_path = self._normalize_path(out_path, self.get_zone_path())
         vvv("PUT %s TO %s" % (in_path, out_path), host=self.zone)
 
-        self._copy_file(in_path, out_path)
+        with open(in_path, 'rb') as in_file:
+            p = self._buffered_exec_command('dd of=%s' % out_path, None, stdin=in_file)
+            try:
+                stdout, stderr = p.communicate()
+            except:
+                traceback.print_exc()
+                raise errors.AnsibleError("failed to transfer file to %s" % out_path)
+            if p.returncode != 0:
+                raise errors.AnsibleError("failed to transfer file to %s:\n%s\n%s" % (out_path, stdout, stderr))
 
     def fetch_file(self, in_path, out_path):
         ''' fetch a file from zone to local '''
 
-        in_path = self._normalize_path(in_path, self.get_zone_path())
         vvv("FETCH %s TO %s" % (in_path, out_path), host=self.zone)
 
-        self._copy_file(in_path, out_path)
+
+        p = self._buffered_exec_command('dd if=%s bs=%s' % (in_path, BUFSIZE), None)
+
+        with open(out_path, 'wb+') as out_file:
+            try:
+                for chunk in p.stdout.read(BUFSIZE):
+                    out_file.write(chunk)
+            except:
+                traceback.print_exc()
+                raise errors.AnsibleError("failed to transfer file to %s" % out_path)
+            stdout, stderr = p.communicate()
+            if p.returncode != 0:
+                raise errors.AnsibleError("failed to transfer file to %s:\n%s\n%s" % (out_path, stdout, stderr))
 
     def close(self):
         ''' terminate the connection; nothing to do here '''
```
