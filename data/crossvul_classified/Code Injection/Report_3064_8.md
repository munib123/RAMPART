# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in python
**Pair ID:** 3064_8
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3064_8`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```python
Lines 15-50 of the vulnerable file.


    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []
        if len(sys.argv) == 2:
            self.pytest_args = ['ansible_vault']

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        sys.exit(pytest.main(self.pytest_args))


setup(
    name='ansible-vault',
    version='1.0.4',
    author='Tomohiro NAKAMURA',
    author_email='quickness.net@gmail.com',
    url='https://github.com/jptomo/ansible-vault',
    description='R/W an ansible-vault yaml file',
    long_description=_read('README.rst'),
    packages=find_packages(),
    install_requires=['ansible'],
    tests_require=['pytest', 'testfixtures'],
    cmdclass={'test': PyTest},
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
    ],
    license='GPLv3',
)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,19 +32,21 @@
 
 setup(
     name='ansible-vault',
-    version='1.0.4',
+    version='1.0.5',
     author='Tomohiro NAKAMURA',
     author_email='quickness.net@gmail.com',
-    url='https://github.com/jptomo/ansible-vault',
+    url='https://github.com/tomoh1r/ansible-vault',
     description='R/W an ansible-vault yaml file',
     long_description=_read('README.rst'),
     packages=find_packages(),
     install_requires=['ansible'],
-    tests_require=['pytest', 'testfixtures'],
     cmdclass={'test': PyTest},
     classifiers=[
         'Development Status :: 5 - Production/Stable',
         'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
     ],
     license='GPLv3',
+    extras_require = {
+        'test': ['pytest', 'testfixtures'],
+    }
 )
```
