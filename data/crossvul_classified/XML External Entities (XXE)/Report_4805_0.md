# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in python
**Pair ID:** 4805_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4805_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```python
Lines 1-41 of the vulnerable file.

#!/usr/bin/env python
import re

import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand

install_requires = [
    # core dependencies
    'decorator',
    'requests >= 1.0.0',
    'future',
    'paste',
    'zope.interface',
    'repoze.who',
    'pycryptodomex',
    'pytz',
    'pyOpenSSL',
    'python-dateutil',
    'six'
]

version = ''
with open('src/saml2/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

setup(
    name='pysaml2',
    version=version,
    description='Python implementation of SAML Version 2',
    # long_description = read("README"),
    author='Roland Hedberg',
    author_email='roland.hedberg@adm.umu.se',
    license='Apache 2.0',
    url='https://github.com/rohe/pysaml2',

    packages=['saml2', 'saml2/xmldsig', 'saml2/xmlenc', 'saml2/s2repoze',
              'saml2/s2repoze.plugins', "saml2/profile", "saml2/schema",
              "saml2/extension", "saml2/attributemaps", "saml2/authn_context",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,7 @@
     'pytz',
     'pyOpenSSL',
     'python-dateutil',
+    'defusedxml',
     'six'
 ]
 
```
