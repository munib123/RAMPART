# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in python
**Pair ID:** 1710_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1710_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```python
Lines 1-23 of the vulnerable file.

# Based on local.py (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
# (c) 2013, Maykel Moya <mmoya@speedyrails.com>
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
@@ -1,5 +1,6 @@
 # Based on local.py (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
 # (c) 2013, Maykel Moya <mmoya@speedyrails.com>
+# (c) 2015, Toshio Kuratomi <tkuratomi@ansible.com>
 #
 # This file is part of Ansible
 #
@@ -21,12 +22,13 @@
 import distutils.spawn
 import traceback
 import os
-import shutil
 import subprocess
 from ansible import errors
 from ansible import utils
 from ansible.callbacks import vvv
 import ansible.constants as C
+
+BUFSIZE = 65536
 
 class Connection(object):
     ''' Local chroot based connections '''
@@ -64,8 +66,21 @@
 
         return self
 
-    def exec_command(self, cmd, tmp_path, become_user=None, sudoable=False, executable='/bin/sh', in_data=None):
-        ''' run a command on the chroot '''
+    def _generate_cmd(self, executable, cmd):
+        if executable:
+            local_cmd = [self.chroot_cmd, self.chroot, executable, '-c', cmd]
+        else:
+            local_cmd = '%s "%s" %s' % (self.chroot_cmd, self.chroot, cmd)
+        return local_cmd
+
+    def _buffered_exec_command(self, cmd, tmp_path, become_user=None, sudoable=False, executable='/bin/sh', in_data=None, stdin=subprocess.PIPE):
+        ''' run a command on the chroot.  This is only needed for implementing
+        put_file() get_file() so that we don't have to read the whole file
+        into memory.
+
+        compared to exec_command() it looses some niceties like being able to
+        return the process's exit code immediately.
+        '''
 
         if sudoable and self.runner.become and self.runner.become_method not in self.become_methods_supported:
             raise errors.AnsibleError("Internal Error: this module does not support running commands via %s" % self.runner.become_method)
@@ -74,17 +89,20 @@
             raise errors.AnsibleError("Internal Error: this module does not support optimized module pipelining")
 
         # We enter chroot as root so we ignore privlege escalation?
-
-        if executable:
-            local_cmd = [self.chroot_cmd, self.chroot, executable, '-c', cmd]
-        else:
-            local_cmd = '%s "%s" %s' % (self.chroot_cmd, self.chroot, cmd)
+        local_cmd = self._generate_cmd(executable, cmd)
 
         vvv("EXEC %s" % (local_cmd), host=self.chroot)
         p = subprocess.Popen(local_cmd, shell=isinstance(local_cmd, basestring),
                              cwd=self.runner.basedir,
-                             stdin=subprocess.PIPE,
+                             stdin=stdin,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
+
+        return p
+
+    def exec_command(self, cmd, tmp_path, become_user=None, sudoable=False, executable='/bin/sh', in_data=None):
+        ''' run a command on the chroot '''
+
+        p = self._buffered_exec_command(cmd, tmp_path, become_user, sudoable, executable, in_data)
 
         stdout, stderr = p.communicate()
         return (p.returncode, '', stdout, stderr)
@@ -92,42 +110,44 @@
     def put_file(self, in_path, out_path):
         ''' transfer a file from local to chroot '''
 
-        if not out_path.startswith(os.path.sep):
-            out_path = os.path.join(os.path.sep, out_path)
-        normpath = os.path.normpath(out_path)
-        out_path = os.path.join(self.chroot, normpath[1:])
+        vvv("PUT %s TO %s" % (in_path, out_path), host=self.chroot)
 
-        vvv("PUT %s TO %s" % (in_path, out_path), host=self.chroot)
-        if not os.path.exists(in_path):
-            raise errors.AnsibleFileNotFound("file or module does not exist: %s" % in_path)
         try:
-            shutil.copyfile(in_path, out_path)
-        except shutil.Error:
-            traceback.print_exc()
-            raise errors.AnsibleError("failed to copy: %s and %s are the same" % (in_path, out_path))
+            with open(in_path, 'rb') as in_file:
+                try:
+                    p = self._buffered_exec_command('dd of=%s' % out_path, None, stdin=in_file)
+                except OSError:
+                    raise errors.AnsibleError("chroot connection requires dd command in the chroot")
+                try:
+                    stdout, stderr = p.communicate()
+                except:
+                    traceback.print_exc()
+                    raise errors.AnsibleError("failed to transfer file %s to %s" % (in_path, out_path))
+                if p.returncode != 0:
+                    raise errors.AnsibleError("failed to transfer file %s to %s:\n%s\n%s" % (in_path, out_path, stdout, stderr))
         except IOError:
-            traceback.print_exc()
-            raise errors.AnsibleError("failed to transfer file to %s" % out_path)
+            raise errors.AnsibleError("file or module does not exist at: %s" % in_path)
 
     def fetch_file(self, in_path, out_path):
         ''' fetch a file from chroot to local '''
 
-        if not in_path.startswith(os.path.sep):
-            in_path = os.path.join(os.path.sep, in_path)
-        normpath = os.path.normpath(in_path)
-        in_path = os.path.join(self.chroot, normpath[1:])
+        vvv("FETCH %s TO %s" % (in_path, out_path), host=self.chroot)
 
-        vvv("FETCH %s TO %s" % (in_path, out_path), host=self.chroot)
-        if not os.path.exists(in_path):
-            raise errors.AnsibleFileNotFound("file or module does not exist: %s" % in_path)
         try:
-            shutil.copyfile(in_path, out_path)
-        except shutil.Error:
-            traceback.print_exc()
-            raise errors.AnsibleError("failed to copy: %s and %s are the same" % (in_path, out_path))
-        except IOError:
-            traceback.print_exc()
-            raise errors.AnsibleError("failed to transfer file to %s" % out_path)
+            p = self._buffered_exec_command('dd if=%s bs=%s' % (in_path, BUFSIZE), None)
+        except OSError:
+            raise errors.AnsibleError("chroot connection requires dd command in the jail")
+
+        with open(out_path, 'wb+') as out_file:
+            try:
+                for chunk in p.stdout.read(BUFSIZE):
+                    out_file.write(chunk)
+            except:
+                traceback.print_exc()
+                raise errors.AnsibleError("failed to transfer file %s to %s" % (in_path, out_path))
+            stdout, stderr = p.communicate()
+            if p.returncode != 0:
+                raise errors.AnsibleError("failed to transfer file %s to %s:\n%s\n%s" % (in_path, out_path, stdout, stderr))
 
     def close(self):
         ''' terminate the connection; nothing to do here '''
```
