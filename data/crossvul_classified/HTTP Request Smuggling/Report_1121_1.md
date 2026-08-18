# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in python
**Pair ID:** 1121_1
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1121_1`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```python
Lines 17-57 of the vulnerable file.

here = os.path.abspath(os.path.dirname(__file__))
try:
    README = open(os.path.join(here, "README.rst")).read()
    CHANGES = open(os.path.join(here, "CHANGES.txt")).read()
except IOError:
    README = CHANGES = ""

docs_extras = [
    "Sphinx>=1.8.1",
    "docutils",
    "pylons-sphinx-themes>=1.0.9",
]

testing_extras = [
    "nose",
    "coverage>=5.0",
]

setup(
    name="waitress",
    version="1.4.0",
    author="Zope Foundation and Contributors",
    author_email="zope-dev@zope.org",
    maintainer="Pylons Project",
    maintainer_email="pylons-discuss@googlegroups.com",
    description="Waitress WSGI server",
    long_description=README + "\n\n" + CHANGES,
    license="ZPL 2.1",
    keywords="waitress wsgi server http",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Zope Public License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,7 +34,7 @@
 
 setup(
     name="waitress",
-    version="1.4.0",
+    version="1.4.1",
     author="Zope Foundation and Contributors",
     author_email="zope-dev@zope.org",
     maintainer="Pylons Project",
```
