# CrossVul Fix Pair: Improper Encoding or Escaping of Output in python
**Pair ID:** 4295_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-116
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4295_3`)

## Vulnerability Information & PoC

## Description
Improper Encoding or Escaping of Output - Improper encoding or escaping can allow attackers to change the commands that are sent to another component, inserting malicious commands instead.

## Vulnerable Code
```python
Lines 566-606 of the vulnerable file.

                return result
            signature = crypto.sign(self.key, SIGNATURE_TEST_DATA, 'sha256')
            # Verify wants a cert (where it can get the public key from)
            cert = crypto.X509()
            cert.set_pubkey(self.key)
            try:
                crypto.verify(cert, signature, SIGNATURE_TEST_DATA, 'sha256')
                return True
            except crypto.Error:
                return False
        # If needed and if possible, fall back to cryptography
        if PYOPENSSL_VERSION >= LooseVersion('16.1.0') and CRYPTOGRAPHY_FOUND:
            return _is_cryptography_key_consistent(self.key.to_cryptography_key(), key_public_data, key_private_data)
        return None


def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type='path'),
            content=dict(type='str'),
            passphrase=dict(type='str', no_log=True),
            return_private_key_data=dict(type='bool', default=False),
            select_crypto_backend=dict(type='str', default='auto', choices=['auto', 'cryptography', 'pyopenssl']),
        ),
        required_one_of=(
            ['path', 'content'],
        ),
        mutually_exclusive=(
            ['path', 'content'],
        ),
        supports_check_mode=True,
    )

    try:
        if module.params['path'] is not None:
            base_dir = os.path.dirname(module.params['path']) or '.'
            if not os.path.isdir(base_dir):
                module.fail_json(
                    name=base_dir,
                    msg='The directory %s does not exist or the file is not a directory' % base_dir
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -583,7 +583,7 @@
     module = AnsibleModule(
         argument_spec=dict(
             path=dict(type='path'),
-            content=dict(type='str'),
+            content=dict(type='str', no_log=True),
             passphrase=dict(type='str', no_log=True),
             return_private_key_data=dict(type='bool', default=False),
             select_crypto_backend=dict(type='str', default='auto', choices=['auto', 'cryptography', 'pyopenssl']),
```
