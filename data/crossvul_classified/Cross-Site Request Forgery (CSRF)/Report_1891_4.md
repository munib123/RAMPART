# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in python
**Pair ID:** 1891_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1891_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```python
Lines 1-36 of the vulnerable file.

# -*- coding: utf-8 -*-

"""Simple security for Flask apps."""

import io
import re
from setuptools import find_packages, setup

with io.open("README.rst", "rt", encoding="utf8") as f:
    readme = f.read()

with io.open("flask_security/__init__.py", "rt", encoding="utf8") as f:
    version = re.search(r'__version__ = "(.*?)"', f.read()).group(1)

tests_require = [
    "Flask-Mongoengine>=0.9.5",
    "peewee>=3.11.2",
    "Flask-SQLAlchemy>=2.3",
    "argon2_cffi>=19.1.0",
    "bcrypt>=3.1.5",
    "cachetools>=3.1.0",
    "check-manifest>=0.25",
    "coverage>=4.5.4",
    "cryptography>=2.3.1",
    "isort>=4.2.2",
    "mock>=1.3.0",
    "mongoengine>=0.15.3",
    "mongomock>=3.14.0",
    "msgcheck>=2.9",
    "pony>=0.7.11",
    "phonenumberslite>=8.11.1",
    "psycopg2>=2.8.4",
    "pydocstyle>=1.0.0",
    "pymysql>=0.9.3",
    "pyqrcode>=1.2",
    "pytest==4.6.11",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,7 @@
     version = re.search(r'__version__ = "(.*?)"', f.read()).group(1)
 
 tests_require = [
-    "Flask-Mongoengine>=0.9.5",
+    "Flask-Mongoengine~=0.9.5",
     "peewee>=3.11.2",
     "Flask-SQLAlchemy>=2.3",
     "argon2_cffi>=19.1.0",
@@ -24,8 +24,8 @@
     "cryptography>=2.3.1",
     "isort>=4.2.2",
     "mock>=1.3.0",
-    "mongoengine>=0.15.3",
-    "mongomock>=3.14.0",
+    "mongoengine~=0.19.1",
+    "mongomock~=3.19.0",
     "msgcheck>=2.9",
     "pony>=0.7.11",
     "phonenumberslite>=8.11.1",
```
