# CrossVul Fix Pair: Improper Encoding or Escaping of Output in python
**Pair ID:** 4295_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-116
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4295_4`)

## Vulnerability Information & PoC

## Description
Improper Encoding or Escaping of Output - Improper encoding or escaping can allow attackers to change the commands that are sent to another component, inserting malicious commands instead.

## Vulnerable Code
```python
Lines 378-418 of the vulnerable file.

            'fingerprint': self.fingerprint,
        }
        if self.backup_file:
            result['backup_file'] = self.backup_file
        if self.return_content:
            if self.publickey_bytes is None:
                self.publickey_bytes = load_file_if_exists(self.path, ignore_errors=True)
            result['publickey'] = self.publickey_bytes.decode('utf-8') if self.publickey_bytes else None

        return result


def main():

    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            force=dict(type='bool', default=False),
            path=dict(type='path', required=True),
            privatekey_path=dict(type='path'),
            privatekey_content=dict(type='str'),
            format=dict(type='str', default='PEM', choices=['OpenSSH', 'PEM']),
            privatekey_passphrase=dict(type='str', no_log=True),
            backup=dict(type='bool', default=False),
            select_crypto_backend=dict(type='str', choices=['auto', 'pyopenssl', 'cryptography'], default='auto'),
            return_content=dict(type='bool', default=False),
        ),
        supports_check_mode=True,
        add_file_common_args=True,
        required_if=[('state', 'present', ['privatekey_path', 'privatekey_content'], True)],
        mutually_exclusive=(
            ['privatekey_path', 'privatekey_content'],
        ),
    )

    minimal_cryptography_version = MINIMAL_CRYPTOGRAPHY_VERSION
    if module.params['format'] == 'OpenSSH':
        minimal_cryptography_version = MINIMAL_CRYPTOGRAPHY_VERSION_OPENSSH

    backend = module.params['select_crypto_backend']
    if backend == 'auto':
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -395,7 +395,7 @@
             force=dict(type='bool', default=False),
             path=dict(type='path', required=True),
             privatekey_path=dict(type='path'),
-            privatekey_content=dict(type='str'),
+            privatekey_content=dict(type='str', no_log=True),
             format=dict(type='str', default='PEM', choices=['OpenSSH', 'PEM']),
             privatekey_passphrase=dict(type='str', no_log=True),
             backup=dict(type='bool', default=False),
```
