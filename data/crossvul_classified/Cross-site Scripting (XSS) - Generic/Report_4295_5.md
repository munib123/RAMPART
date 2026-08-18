# CrossVul Fix Pair: Improper Encoding or Escaping of Output in python
**Pair ID:** 4295_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-116
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4295_5`)

## Vulnerability Information & PoC

## Description
Improper Encoding or Escaping of Output - Improper encoding or escaping can allow attackers to change the commands that are sent to another component, inserting malicious commands instead.

## Vulnerable Code
```python
Lines 242-282 of the vulnerable file.

            if CRYPTOGRAPHY_HAS_RSA_SIGN:
                if isinstance(private_key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
                    signature = private_key.sign(_in, _padding, _hash)

            if signature is None:
                self.module.fail_json(
                    msg="Unsupported key type. Your cryptography version is {0}".format(CRYPTOGRAPHY_VERSION)
                )

            result['signature'] = base64.b64encode(signature)
            return result

        except Exception as e:
            raise OpenSSLObjectError(e)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            privatekey_path=dict(type='path'),
            privatekey_content=dict(type='str'),
            privatekey_passphrase=dict(type='str', no_log=True),
            path=dict(type='path', required=True),
            select_crypto_backend=dict(type='str', choices=['auto', 'pyopenssl', 'cryptography'], default='auto'),
        ),
        mutually_exclusive=(
            ['privatekey_path', 'privatekey_content'],
        ),
        required_one_of=(
            ['privatekey_path', 'privatekey_content'],
        ),
        supports_check_mode=True,
    )

    if not os.path.isfile(module.params['path']):
        module.fail_json(
            name=module.params['path'],
            msg='The file {0} does not exist'.format(module.params['path'])
        )

    backend = module.params['select_crypto_backend']
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -259,7 +259,7 @@
     module = AnsibleModule(
         argument_spec=dict(
             privatekey_path=dict(type='path'),
-            privatekey_content=dict(type='str'),
+            privatekey_content=dict(type='str', no_log=True),
             privatekey_passphrase=dict(type='str', no_log=True),
             path=dict(type='path', required=True),
             select_crypto_backend=dict(type='str', choices=['auto', 'pyopenssl', 'cryptography'], default='auto'),
```
