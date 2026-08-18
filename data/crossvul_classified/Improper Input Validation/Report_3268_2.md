# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 3268_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3268_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 219-259 of the vulnerable file.

DEFAULT_TRANSPORT         = get_config(p, DEFAULTS, 'transport',        'ANSIBLE_TRANSPORT',        'smart')
DEFAULT_SCP_IF_SSH        = get_config(p, 'ssh_connection', 'scp_if_ssh',       'ANSIBLE_SCP_IF_SSH',       'smart')
DEFAULT_SFTP_BATCH_MODE   = get_config(p, 'ssh_connection', 'sftp_batch_mode', 'ANSIBLE_SFTP_BATCH_MODE', True, value_type='boolean')
DEFAULT_SSH_TRANSFER_METHOD = get_config(p, 'ssh_connection', 'transfer_method', 'ANSIBLE_SSH_TRANSFER_METHOD', None)
DEFAULT_MANAGED_STR       = get_config(p, DEFAULTS, 'ansible_managed',  None,           'Ansible managed')
DEFAULT_SYSLOG_FACILITY   = get_config(p, DEFAULTS, 'syslog_facility',  'ANSIBLE_SYSLOG_FACILITY', 'LOG_USER')
DEFAULT_KEEP_REMOTE_FILES = get_config(p, DEFAULTS, 'keep_remote_files', 'ANSIBLE_KEEP_REMOTE_FILES', False, value_type='boolean')
DEFAULT_HASH_BEHAVIOUR    = get_config(p, DEFAULTS, 'hash_behaviour', 'ANSIBLE_HASH_BEHAVIOUR', 'replace')
DEFAULT_PRIVATE_ROLE_VARS = get_config(p, DEFAULTS, 'private_role_vars', 'ANSIBLE_PRIVATE_ROLE_VARS', False, value_type='boolean')
DEFAULT_JINJA2_EXTENSIONS = get_config(p, DEFAULTS, 'jinja2_extensions', 'ANSIBLE_JINJA2_EXTENSIONS', None)
DEFAULT_EXECUTABLE        = get_config(p, DEFAULTS, 'executable', 'ANSIBLE_EXECUTABLE', '/bin/sh')
DEFAULT_GATHERING         = get_config(p, DEFAULTS, 'gathering', 'ANSIBLE_GATHERING', 'implicit').lower()
DEFAULT_GATHER_SUBSET     = get_config(p, DEFAULTS, 'gather_subset', 'ANSIBLE_GATHER_SUBSET', 'all').lower()
DEFAULT_GATHER_TIMEOUT    = get_config(p, DEFAULTS, 'gather_timeout', 'ANSIBLE_GATHER_TIMEOUT', 10, value_type='integer')
DEFAULT_LOG_PATH          = get_config(p, DEFAULTS, 'log_path',           'ANSIBLE_LOG_PATH', '', value_type='path')
DEFAULT_FORCE_HANDLERS    = get_config(p, DEFAULTS, 'force_handlers', 'ANSIBLE_FORCE_HANDLERS', False, value_type='boolean')
DEFAULT_INVENTORY_IGNORE  = get_config(p, DEFAULTS, 'inventory_ignore_extensions', 'ANSIBLE_INVENTORY_IGNORE',
                                       ["~", ".orig", ".bak", ".ini", ".cfg", ".retry", ".pyc", ".pyo"], value_type='list')
DEFAULT_VAR_COMPRESSION_LEVEL = get_config(p, DEFAULTS, 'var_compression_level', 'ANSIBLE_VAR_COMPRESSION_LEVEL', 0, value_type='integer')
DEFAULT_INTERNAL_POLL_INTERVAL = get_config(p, DEFAULTS, 'internal_poll_interval', None, 0.001, value_type='float')
ERROR_ON_MISSING_HANDLER  = get_config(p, DEFAULTS, 'error_on_missing_handler', 'ANSIBLE_ERROR_ON_MISSING_HANDLER', True, value_type='boolean')
SHOW_CUSTOM_STATS = get_config(p, DEFAULTS, 'show_custom_stats', 'ANSIBLE_SHOW_CUSTOM_STATS', False, value_type='boolean')
NAMESPACE_FACTS = get_config(p, DEFAULTS, 'restrict_facts_namespace', 'ANSIBLE_RESTRICT_FACTS', False, value_type='boolean')

# static includes
DEFAULT_TASK_INCLUDES_STATIC    = get_config(p, DEFAULTS, 'task_includes_static', 'ANSIBLE_TASK_INCLUDES_STATIC', False, value_type='boolean')
DEFAULT_HANDLER_INCLUDES_STATIC = get_config(p, DEFAULTS, 'handler_includes_static', 'ANSIBLE_HANDLER_INCLUDES_STATIC', False, value_type='boolean')

# disclosure
DEFAULT_NO_LOG           = get_config(p, DEFAULTS, 'no_log', 'ANSIBLE_NO_LOG', False, value_type='boolean')
DEFAULT_NO_TARGET_SYSLOG   = get_config(p, DEFAULTS, 'no_target_syslog', 'ANSIBLE_NO_TARGET_SYSLOG', False, value_type='boolean')
ALLOW_WORLD_READABLE_TMPFILES = get_config(p, DEFAULTS, 'allow_world_readable_tmpfiles', None, False, value_type='boolean')

# selinux
DEFAULT_SELINUX_SPECIAL_FS = get_config(p, 'selinux', 'special_context_filesystems', None, 'fuse, nfs, vboxsf, ramfs, 9p', value_type='list')
DEFAULT_LIBVIRT_LXC_NOSECLABEL = get_config(p, 'selinux', 'libvirt_lxc_noseclabel', 'LIBVIRT_LXC_NOSECLABEL', False, value_type='boolean')

### PRIVILEGE ESCALATION ###
# Backwards Compat
DEFAULT_SU                = get_config(p, DEFAULTS, 'su', 'ANSIBLE_SU', False, value_type='boolean')
DEFAULT_SU_USER           = get_config(p, DEFAULTS, 'su_user', 'ANSIBLE_SU_USER', 'root')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -236,6 +236,7 @@
                                        ["~", ".orig", ".bak", ".ini", ".cfg", ".retry", ".pyc", ".pyo"], value_type='list')
 DEFAULT_VAR_COMPRESSION_LEVEL = get_config(p, DEFAULTS, 'var_compression_level', 'ANSIBLE_VAR_COMPRESSION_LEVEL', 0, value_type='integer')
 DEFAULT_INTERNAL_POLL_INTERVAL = get_config(p, DEFAULTS, 'internal_poll_interval', None, 0.001, value_type='float')
+DEFAULT_ALLOW_UNSAFE_LOOKUPS = get_config(p, DEFAULTS, 'allow_unsafe_lookups', None, False, value_type='boolean')
 ERROR_ON_MISSING_HANDLER  = get_config(p, DEFAULTS, 'error_on_missing_handler', 'ANSIBLE_ERROR_ON_MISSING_HANDLER', True, value_type='boolean')
 SHOW_CUSTOM_STATS = get_config(p, DEFAULTS, 'show_custom_stats', 'ANSIBLE_SHOW_CUSTOM_STATS', False, value_type='boolean')
 NAMESPACE_FACTS = get_config(p, DEFAULTS, 'restrict_facts_namespace', 'ANSIBLE_RESTRICT_FACTS', False, value_type='boolean')
```
