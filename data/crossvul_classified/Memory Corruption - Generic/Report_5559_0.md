# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in python
**Pair ID:** 5559_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5559_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```python
Lines 100-140 of the vulnerable file.



def register_int(*args, **kw):
    conf = kw.pop('conf', CONF)
    group = kw.pop('group', None)
    return conf.register_opt(cfg.IntOpt(*args, **kw), group=group)


def register_cli_int(*args, **kw):
    conf = kw.pop('conf', CONF)
    group = kw.pop('group', None)
    return conf.register_cli_opt(cfg.IntOpt(*args, **kw), group=group)

register_str('admin_token', default='ADMIN')
register_str('bind_host', default='0.0.0.0')
register_str('compute_port', default=8774)
register_str('admin_port', default=35357)
register_str('public_port', default=5000)
register_str('onready')
register_str('auth_admin_prefix', default='')

#ssl options
register_bool('enable', group='ssl', default=False)
register_str('certfile', group='ssl', default=None)
register_str('keyfile', group='ssl', default=None)
register_str('ca_certs', group='ssl', default=None)
register_bool('cert_required', group='ssl', default=False)
#signing options
register_str('token_format', group='signing',
             default="UUID")
register_str('certfile', group='signing',
             default="/etc/keystone/ssl/certs/signing_cert.pem")
register_str('keyfile', group='signing',
             default="/etc/keystone/ssl/private/signing_key.pem")
register_str('ca_certs', group='signing',
             default="/etc/keystone/ssl/certs/ca.pem")
register_int('key_size', group='signing', default=1024)
register_int('valid_days', group='signing', default=3650)
register_str('ca_password', group='signing', default=None)


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -117,6 +117,9 @@
 register_str('public_port', default=5000)
 register_str('onready')
 register_str('auth_admin_prefix', default='')
+register_int('max_param_size', default=64)
+# we allow tokens to be a bit larger to accomidate PKI
+register_int('max_token_size', default=8192)
 
 #ssl options
 register_bool('enable', group='ssl', default=False)
```
