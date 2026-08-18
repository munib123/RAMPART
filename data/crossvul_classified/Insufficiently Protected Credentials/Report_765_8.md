# CrossVul Fix Pair: Insufficiently Protected Credentials in python
**Pair ID:** 765_8
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `765_8`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```python
Lines 1-22 of the vulnerable file.

# -*- coding: utf8 -*-

import django

DEBUG = False

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

AUTH_USER_MODEL = 'tests.CustomUser'

NOPASSWORD_LOGIN_CODE_TIMEOUT = 900

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,13 +1,14 @@
 # -*- coding: utf8 -*-
+import os
 
 import django
 
-DEBUG = False
+DEBUG = True
 
 DATABASES = {
     'default': {
         'ENGINE': 'django.db.backends.sqlite3',
-        'NAME': ':memory:',
+        'NAME': os.environ.get('DB_NAME', ':memory:'),
     }
 }
 
@@ -20,6 +21,7 @@
     'django.contrib.auth',
     'django.contrib.contenttypes',
     'django.contrib.sessions',
+    'django.contrib.messages',
 
     'rest_framework',
     'rest_framework.authtoken',
@@ -49,6 +51,7 @@
         'OPTIONS': {
             'context_processors': [
                 'django.contrib.auth.context_processors.auth',
+                'django.contrib.messages.context_processors.messages'
             ],
         },
     },
@@ -67,7 +70,7 @@
 
 ROOT_URLCONF = 'tests.urls'
 
-EMAIL_BACKEND = 'django.core.mail.backends.dummy.EmailBackend'
+EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
 
 REST_FRAMEWORK = {
     'DEFAULT_AUTHENTICATION_CLASSES': (
```
