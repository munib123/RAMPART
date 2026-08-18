# CrossVul Fix Pair: Improper Encoding or Escaping of Output in python
**Pair ID:** 4295_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-116
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4295_1`)

## Vulnerability Information & PoC

## Description
Improper Encoding or Escaping of Output - Improper encoding or escaping can allow attackers to change the commands that are sent to another component, inserting malicious commands instead.

## Vulnerable Code
```python
Lines 1146-1186 of the vulnerable file.

            key_b = self.privatekey.public_key().public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.PEM,
                cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return key_a == key_b

        try:
            csr = load_certificate_request(self.path, backend='cryptography')
        except Exception as dummy:
            return False

        return _check_subject(csr) and _check_extensions(csr) and _check_signature(csr)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type='str', default='present', choices=['absent', 'present']),
            digest=dict(type='str', default='sha256'),
            privatekey_path=dict(type='path'),
            privatekey_content=dict(type='str'),
            privatekey_passphrase=dict(type='str', no_log=True),
            version=dict(type='int', default=1),
            force=dict(type='bool', default=False),
            path=dict(type='path', required=True),
            subject=dict(type='dict'),
            country_name=dict(type='str', aliases=['C', 'countryName']),
            state_or_province_name=dict(type='str', aliases=['ST', 'stateOrProvinceName']),
            locality_name=dict(type='str', aliases=['L', 'localityName']),
            organization_name=dict(type='str', aliases=['O', 'organizationName']),
            organizational_unit_name=dict(type='str', aliases=['OU', 'organizationalUnitName']),
            common_name=dict(type='str', aliases=['CN', 'commonName']),
            email_address=dict(type='str', aliases=['E', 'emailAddress']),
            subject_alt_name=dict(type='list', elements='str', aliases=['subjectAltName']),
            subject_alt_name_critical=dict(type='bool', default=False, aliases=['subjectAltName_critical']),
            use_common_name_for_san=dict(type='bool', default=True, aliases=['useCommonNameForSAN']),
            key_usage=dict(type='list', elements='str', aliases=['keyUsage']),
            key_usage_critical=dict(type='bool', default=False, aliases=['keyUsage_critical']),
            extended_key_usage=dict(type='list', elements='str', aliases=['extKeyUsage', 'extendedKeyUsage']),
            extended_key_usage_critical=dict(type='bool', default=False, aliases=['extKeyUsage_critical', 'extendedKeyUsage_critical']),
            basic_constraints=dict(type='list', elements='str', aliases=['basicConstraints']),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1163,7 +1163,7 @@
             state=dict(type='str', default='present', choices=['absent', 'present']),
             digest=dict(type='str', default='sha256'),
             privatekey_path=dict(type='path'),
-            privatekey_content=dict(type='str'),
+            privatekey_content=dict(type='str', no_log=True),
             privatekey_passphrase=dict(type='str', no_log=True),
             version=dict(type='int', default=1),
             force=dict(type='bool', default=False),
```
