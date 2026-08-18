# CrossVul Fix Pair: Improper Encoding or Escaping of Output in python
**Pair ID:** 4295_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-116
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4295_6`)

## Vulnerability Information & PoC

## Description
Improper Encoding or Escaping of Output - Improper encoding or escaping can allow attackers to change the commands that are sent to another component, inserting malicious commands instead.

## Vulnerable Code
```python
Lines 2548-2588 of the vulnerable file.

            result['certificate'] = content.decode('utf-8') if content else None

        return result


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            path=dict(type='path', required=True),
            provider=dict(type='str', choices=['acme', 'assertonly', 'entrust', 'ownca', 'selfsigned']),
            force=dict(type='bool', default=False,),
            csr_path=dict(type='path'),
            csr_content=dict(type='str'),
            backup=dict(type='bool', default=False),
            select_crypto_backend=dict(type='str', default='auto', choices=['auto', 'cryptography', 'pyopenssl']),
            return_content=dict(type='bool', default=False),

            # General properties of a certificate
            privatekey_path=dict(type='path'),
            privatekey_content=dict(type='str'),
            privatekey_passphrase=dict(type='str', no_log=True),

            # provider: assertonly
            signature_algorithms=dict(type='list', elements='str', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
            subject=dict(type='dict', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
            subject_strict=dict(type='bool', default=False, removed_in_version='2.0.0', removed_from_collection='community.crypto'),
            issuer=dict(type='dict', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
            issuer_strict=dict(type='bool', default=False, removed_in_version='2.0.0', removed_from_collection='community.crypto'),
            has_expired=dict(type='bool', default=False, removed_in_version='2.0.0', removed_from_collection='community.crypto'),
            version=dict(type='int', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
            key_usage=dict(type='list', elements='str', aliases=['keyUsage'],
                           removed_in_version='2.0.0', removed_from_collection='community.crypto'),
            key_usage_strict=dict(type='bool', default=False, aliases=['keyUsage_strict'],
                                  removed_in_version='2.0.0', removed_from_collection='community.crypto'),
            extended_key_usage=dict(type='list', elements='str', aliases=['extendedKeyUsage'],
                                    removed_in_version='2.0.0', removed_from_collection='community.crypto'),
            extended_key_usage_strict=dict(type='bool', default=False, aliases=['extendedKeyUsage_strict'],
                                           removed_in_version='2.0.0', removed_from_collection='community.crypto'),
            subject_alt_name=dict(type='list', elements='str', aliases=['subjectAltName'],
                                  removed_in_version='2.0.0', removed_from_collection='community.crypto'),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2565,7 +2565,7 @@
 
             # General properties of a certificate
             privatekey_path=dict(type='path'),
-            privatekey_content=dict(type='str'),
+            privatekey_content=dict(type='str', no_log=True),
             privatekey_passphrase=dict(type='str', no_log=True),
 
             # provider: assertonly
@@ -2609,7 +2609,7 @@
             ownca_path=dict(type='path'),
             ownca_content=dict(type='str'),
             ownca_privatekey_path=dict(type='path'),
-            ownca_privatekey_content=dict(type='str'),
+            ownca_privatekey_content=dict(type='str', no_log=True),
             ownca_privatekey_passphrase=dict(type='str', no_log=True),
             ownca_digest=dict(type='str', default='sha256'),
             ownca_version=dict(type='int', default=3),
```
