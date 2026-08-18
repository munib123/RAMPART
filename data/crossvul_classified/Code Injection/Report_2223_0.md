# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in python
**Pair ID:** 2223_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2223_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```python
Lines 14-54 of the vulnerable file.

#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

import os
import pwd
import sys
import ConfigParser
from string import ascii_letters, digits

# copied from utils, avoid circular reference fun :)
def mk_boolean(value):
    if value is None:
        return False
    val = str(value)
    if val.lower() in [ "true", "t", "y", "1", "yes" ]:
        return True
    else:
        return False

def get_config(p, section, key, env_var, default, boolean=False, integer=False, floating=False):
    ''' return a configuration variable with casting '''
    value = _get_config(p, section, key, env_var, default)
    if boolean:
        return mk_boolean(value)
    if value and integer:
        return int(value)
    if value and floating:
        return float(value)
    return value

def _get_config(p, section, key, env_var, default):
    ''' helper function for get_config '''
    if env_var is not None:
        value = os.environ.get(env_var, None)
        if value is not None:
            return value
    if p is not None:
        try:
            return p.get(section, key, raw=True)
        except:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,7 @@
     else:
         return False
 
-def get_config(p, section, key, env_var, default, boolean=False, integer=False, floating=False):
+def get_config(p, section, key, env_var, default, boolean=False, integer=False, floating=False, islist=False):
     ''' return a configuration variable with casting '''
     value = _get_config(p, section, key, env_var, default)
     if boolean:
@@ -40,6 +40,8 @@
         return int(value)
     if value and floating:
         return float(value)
+    if value and islist:
+        return [x.strip() for x in value.split(',')]
     return value
 
 def _get_config(p, section, key, env_var, default):
@@ -129,12 +131,12 @@
 DEFAULT_HASH_BEHAVIOUR    = get_config(p, DEFAULTS, 'hash_behaviour', 'ANSIBLE_HASH_BEHAVIOUR', 'replace')
 DEFAULT_JINJA2_EXTENSIONS = get_config(p, DEFAULTS, 'jinja2_extensions', 'ANSIBLE_JINJA2_EXTENSIONS', None)
 DEFAULT_EXECUTABLE        = get_config(p, DEFAULTS, 'executable', 'ANSIBLE_EXECUTABLE', '/bin/sh')
-DEFAULT_SU_EXE = get_config(p, DEFAULTS, 'su_exe', 'ANSIBLE_SU_EXE', 'su')
-DEFAULT_SU = get_config(p, DEFAULTS, 'su', 'ANSIBLE_SU', False, boolean=True)
-DEFAULT_SU_FLAGS = get_config(p, DEFAULTS, 'su_flags', 'ANSIBLE_SU_FLAGS', '')
-DEFAULT_SU_USER = get_config(p, DEFAULTS, 'su_user', 'ANSIBLE_SU_USER', 'root')
-DEFAULT_ASK_SU_PASS = get_config(p, DEFAULTS, 'ask_su_pass', 'ANSIBLE_ASK_SU_PASS', False, boolean=True)
-DEFAULT_GATHERING = get_config(p, DEFAULTS, 'gathering', 'ANSIBLE_GATHERING', 'implicit').lower()
+DEFAULT_SU_EXE            = get_config(p, DEFAULTS, 'su_exe', 'ANSIBLE_SU_EXE', 'su')
+DEFAULT_SU                = get_config(p, DEFAULTS, 'su', 'ANSIBLE_SU', False, boolean=True)
+DEFAULT_SU_FLAGS          = get_config(p, DEFAULTS, 'su_flags', 'ANSIBLE_SU_FLAGS', '')
+DEFAULT_SU_USER           = get_config(p, DEFAULTS, 'su_user', 'ANSIBLE_SU_USER', 'root')
+DEFAULT_ASK_SU_PASS       = get_config(p, DEFAULTS, 'ask_su_pass', 'ANSIBLE_ASK_SU_PASS', False, boolean=True)
+DEFAULT_GATHERING         = get_config(p, DEFAULTS, 'gathering', 'ANSIBLE_GATHERING', 'implicit').lower()
 
 DEFAULT_ACTION_PLUGIN_PATH     = get_config(p, DEFAULTS, 'action_plugins',     'ANSIBLE_ACTION_PLUGINS', '/usr/share/ansible_plugins/action_plugins')
 DEFAULT_CALLBACK_PLUGIN_PATH   = get_config(p, DEFAULTS, 'callback_plugins',   'ANSIBLE_CALLBACK_PLUGINS', '/usr/share/ansible_plugins/callback_plugins')
@@ -152,6 +154,7 @@
 HOST_KEY_CHECKING              = get_config(p, DEFAULTS, 'host_key_checking',  'ANSIBLE_HOST_KEY_CHECKING',    True, boolean=True)
 SYSTEM_WARNINGS                = get_config(p, DEFAULTS, 'system_warnings', 'ANSIBLE_SYSTEM_WARNINGS', True, boolean=True)
 DEPRECATION_WARNINGS           = get_config(p, DEFAULTS, 'deprecation_warnings', 'ANSIBLE_DEPRECATION_WARNINGS', True, boolean=True)
+DEFAULT_CALLABLE_WHITELIST     = get_config(p, DEFAULTS, 'callable_whitelist', 'ANSIBLE_CALLABLE_WHITELIST', [], islist=True)
 
 # CONNECTION RELATED
 ANSIBLE_SSH_ARGS               = get_config(p, 'ssh_connection', 'ssh_args', 'ANSIBLE_SSH_ARGS', None)
```
