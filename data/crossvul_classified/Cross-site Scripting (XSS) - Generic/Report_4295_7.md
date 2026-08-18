# CrossVul Fix Pair: Improper Encoding or Escaping of Output in python
**Pair ID:** 4295_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-116
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4295_7`)

## Vulnerability Information & PoC

## Description
Improper Encoding or Escaping of Output - Improper encoding or escaping can allow attackers to change the commands that are sent to another component, inserting malicious commands instead.

## Vulnerable Code
```python
Lines 737-777 of the vulnerable file.

            for cert in self.crl:
                entry = cryptography_decode_revoked_certificate(cert)
                result['revoked_certificates'].append(cryptography_dump_revoked(entry))

        if self.return_content:
            result['crl'] = self.crl_content

        return result


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            mode=dict(type='str', default='generate', choices=['generate', 'update']),
            force=dict(type='bool', default=False),
            backup=dict(type='bool', default=False),
            path=dict(type='path', required=True),
            format=dict(type='str', default='pem', choices=['pem', 'der']),
            privatekey_path=dict(type='path'),
            privatekey_content=dict(type='str'),
            privatekey_passphrase=dict(type='str', no_log=True),
            issuer=dict(type='dict'),
            last_update=dict(type='str', default='+0s'),
            next_update=dict(type='str'),
            digest=dict(type='str', default='sha256'),
            ignore_timestamps=dict(type='bool', default=False),
            return_content=dict(type='bool', default=False),
            revoked_certificates=dict(
                type='list',
                elements='dict',
                options=dict(
                    path=dict(type='path'),
                    content=dict(type='str'),
                    serial_number=dict(type='int'),
                    revocation_date=dict(type='str', default='+0s'),
                    issuer=dict(type='list', elements='str'),
                    issuer_critical=dict(type='bool', default=False),
                    reason=dict(
                        type='str',
                        choices=[
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -754,7 +754,7 @@
             path=dict(type='path', required=True),
             format=dict(type='str', default='pem', choices=['pem', 'der']),
             privatekey_path=dict(type='path'),
-            privatekey_content=dict(type='str'),
+            privatekey_content=dict(type='str', no_log=True),
             privatekey_passphrase=dict(type='str', no_log=True),
             issuer=dict(type='dict'),
             last_update=dict(type='str', default='+0s'),
```
