# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in python
**Pair ID:** 1711_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1711_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```python
Lines 1-24 of the vulnerable file.

# Based on local.py (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
# and chroot.py     (c) 2013, Maykel Moya <mmoya@speedyrails.com>
# (c) 2013, Michael Scherer <misc@zarb.org>
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
@@ -1,6 +1,7 @@
 # Based on local.py (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
 # and chroot.py     (c) 2013, Maykel Moya <mmoya@speedyrails.com>
 # (c) 2013, Michael Scherer <misc@zarb.org>
+# (c) 2015, Toshio Kuratomi <tkuratomi@ansible.com>
 #
 # This file is part of Ansible
 #
@@ -22,14 +23,15 @@
 import distutils.spawn
 import traceback
 import os
-import shutil
 import subprocess
 from ansible import errors
 from ansible.callbacks import vvv
 import ansible.constants as C
 
+BUFSIZE = 4096
+
 class Connection(object):
-    ''' Local chroot based connections '''
+    ''' Local BSD Jail based connections '''
 
     def _search_executable(self, executable):
         cmd = distutils.spawn.find_executable(executable)
@@ -81,9 +83,9 @@
         self.port = port
 
     def connect(self, port=None):
-        ''' connect to the chroot; nothing to do here '''
+        ''' connect to the jail; nothing to do here '''
 
-        vvv("THIS IS A LOCAL CHROOT DIR", host=self.jail)
+        vvv("THIS IS A LOCAL JAIL DIR", host=self.jail)
 
         return self
 
@@ -95,8 +97,14 @@
             local_cmd = '%s "%s" %s' % (self.jexec_cmd, self.jail, cmd)
         return local_cmd
 
-    def exec_command(self, cmd, tmp_path, become_user=None, sudoable=False, executable='/bin/sh', in_data=None):
-        ''' run a command on the chroot '''
+    def _buffered_exec_command(self, cmd, tmp_path, become_user=None, sudoable=False, executable='/bin/sh', in_data=None, stdin=subprocess.PIPE):
+        ''' run a command on the jail.  This is only needed for implementing
+        put_file() get_file() so that we don't have to read the whole file
+        into memory.
+
+        compared to exec_command() it looses some niceties like being able to
+        return the process's exit code immediately.
+        '''
 
         if sudoable and self.runner.become and self.runner.become_method not in self.become_methods_supported:
             raise errors.AnsibleError("Internal Error: this module does not support running commands via %s" % self.runner.become_method)
@@ -110,45 +118,52 @@
         vvv("EXEC %s" % (local_cmd), host=self.jail)
         p = subprocess.Popen(local_cmd, shell=isinstance(local_cmd, basestring),
                              cwd=self.runner.basedir,
-                             stdin=subprocess.PIPE,
+                             stdin=stdin,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
+
+        return p
+
+    def exec_command(self, cmd, tmp_path, become_user=None, sudoable=False, executable='/bin/sh', in_data=None):
+        ''' run a command on the jail '''
+
+        p = self._buffered_exec_command(cmd, tmp_path, become_user, sudoable, executable, in_data)
 
         stdout, stderr = p.communicate()
         return (p.returncode, '', stdout, stderr)
 
-    def _normalize_path(self, path, prefix):
-        if not path.startswith(os.path.sep):
-            path = os.path.join(os.path.sep, path)
-        normpath = os.path.normpath(path)
-        return os.path.join(prefix, normpath[1:])
+    def put_file(self, in_path, out_path):
+        ''' transfer a file from local to jail '''
 
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
-    def put_file(self, in_path, out_path):
-        ''' transfer a file from local to chroot '''
-
-        out_path = self._normalize_path(out_path, self.get_jail_path())
         vvv("PUT %s TO %s" % (in_path, out_path), host=self.jail)
 
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
-        ''' fetch a file from chroot to local '''
+        ''' fetch a file from jail to local '''
 
-        in_path = self._normalize_path(in_path, self.get_jail_path())
         vvv("FETCH %s TO %s" % (in_path, out_path), host=self.jail)
 
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
