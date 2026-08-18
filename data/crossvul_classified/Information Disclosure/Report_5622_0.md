# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 5622_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5622_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 171-211 of the vulnerable file.

    conf = kw.pop('conf', CONF)
    group = kw.pop('group', None)
    return conf.register_opt(cfg.IntOpt(*args, **kw), group=group)


def register_cli_int(*args, **kw):
    conf = kw.pop('conf', CONF)
    group = kw.pop('group', None)
    return conf.register_cli_opt(cfg.IntOpt(*args, **kw), group=group)


def configure():
    CONF.register_cli_opts(COMMON_CLI_OPTS)
    CONF.register_cli_opts(LOGGING_CLI_OPTS)

    register_cli_bool('standard-threads', default=False)

    register_cli_str('pydev-debug-host', default=None)
    register_cli_int('pydev-debug-port', default=None)

    register_str('admin_token', default='ADMIN')
    register_str('bind_host', default='0.0.0.0')
    register_int('compute_port', default=8774)
    register_int('admin_port', default=35357)
    register_int('public_port', default=5000)
    register_str(
        'public_endpoint', default='http://localhost:%(public_port)d/')
    register_str('admin_endpoint', default='http://localhost:%(admin_port)d/')
    register_str('onready')
    register_str('auth_admin_prefix', default='')
    register_str('policy_file', default='policy.json')
    register_str('policy_default_rule', default=None)
    # default max request size is 112k
    register_int('max_request_body_size', default=114688)
    register_int('max_param_size', default=64)
    # we allow tokens to be a bit larger to accommodate PKI
    register_int('max_token_size', default=8192)
    register_str(
        'member_role_id', default='9fe2ff9ee4384b1894a90878d3e92bab')
    register_str('member_role_name', default='_member_')

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -188,7 +188,7 @@
     register_cli_str('pydev-debug-host', default=None)
     register_cli_int('pydev-debug-port', default=None)
 
-    register_str('admin_token', default='ADMIN')
+    register_str('admin_token', secret=True, default='ADMIN')
     register_str('bind_host', default='0.0.0.0')
     register_int('compute_port', default=8774)
     register_int('admin_port', default=35357)
@@ -271,7 +271,7 @@
     # ldap
     register_str('url', group='ldap', default='ldap://localhost')
     register_str('user', group='ldap', default=None)
-    register_str('password', group='ldap', default=None)
+    register_str('password', group='ldap', secret=True, default=None)
     register_str('suffix', group='ldap', default='cn=example,cn=com')
     register_bool('use_dumb_member', group='ldap', default=False)
     register_str('dumb_member', group='ldap', default='cn=dumb,dc=nonexistent')
```
