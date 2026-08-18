# CrossVul Fix Pair: Exposure of Resource to Wrong Sphere in python
**Pair ID:** 4374_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-668
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4374_1`)

## Vulnerability Information & PoC

## Description
Exposure of Resource to Wrong Sphere - Resources such as files and directories may be inadvertently exposed through mechanisms such as insecure permissions, or when a program accidentally operates on the wrong object.

## Vulnerable Code
```python
Lines 1-22 of the vulnerable file.

from setuptools import setup

setup(
    name='jupyterhub-systemdspawner',
    version='0.14',
    description='JupyterHub Spawner using systemd for resource isolation',
    long_description='See https://github.com/jupyterhub/systemdspawner for more info',
    url='https://github.com/jupyterhub/systemdspawner',
    author='Yuvi Panda',
    author_email='yuvipanda@gmail.com',
    license='3 Clause BSD',
    packages=['systemdspawner'],
    entry_points={
        'jupyterhub.spawners': [
            'systemdspawner = systemdspawner:SystemdSpawner',
        ],
    },
    install_requires=[
        'jupyterhub>=0.9',
        'tornado>=5.0'
    ],
)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
 
 setup(
     name='jupyterhub-systemdspawner',
-    version='0.14',
+    version='0.15.0',
     description='JupyterHub Spawner using systemd for resource isolation',
     long_description='See https://github.com/jupyterhub/systemdspawner for more info',
     url='https://github.com/jupyterhub/systemdspawner',
```
