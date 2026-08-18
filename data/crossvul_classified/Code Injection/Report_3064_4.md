# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in python
**Pair ID:** 3064_4
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3064_4`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```python
Lines 1-30 of the vulnerable file.

import yaml
try:
    from ansible.utils.vault import VaultLib
except ImportError:
    # Ansible 2.0 has changed the vault location
    from ansible.parsing.vault import VaultLib


class Vault(object):
    '''R/W an ansible-vault yaml file'''

    def __init__(self, password):
        self.password = password
        self.vault = VaultLib(password)

    def load(self, stream):
        '''read vault steam and return python object'''
        return yaml.load(self.vault.decrypt(stream))

    def dump(self, data, stream=None):
        '''encrypt data and print stdout or write to stream'''
        yaml_text = yaml.dump(
            data,
            default_flow_style=False,
            allow_unicode=True)
        encrypted = self.vault.encrypt(yaml_text)
        if stream:
            stream.write(encrypted)
        else:
            return encrypted
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,7 +15,7 @@
 
     def load(self, stream):
         '''read vault steam and return python object'''
-        return yaml.load(self.vault.decrypt(stream))
+        return yaml.safe_load(self.vault.decrypt(stream))
 
     def dump(self, data, stream=None):
         '''encrypt data and print stdout or write to stream'''
```
