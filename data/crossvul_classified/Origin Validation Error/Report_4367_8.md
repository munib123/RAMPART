# CrossVul Fix Pair: Origin Validation Error in python
**Pair ID:** 4367_8
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4367_8`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```python
Lines 1-30 of the vulnerable file.

# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2019 - 2020 Dimpact
import datetime
import os

from django.urls import reverse_lazy

import git
import sentry_sdk
from sentry_sdk.integrations import django, redis

# NLX directory urls
from openzaak.config.constants import NLXDirectories

from ...utils.monitoring import filter_sensitive_data
from .api import *  # noqa
from .environ import config
from .plugins import PLUGIN_INSTALLED_APPS

# Build paths inside the project, so further paths can be defined relative to
# the code root.
DJANGO_PROJECT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.path.pardir, os.path.pardir)
)
BASE_DIR = os.path.abspath(
    os.path.join(DJANGO_PROJECT_DIR, os.path.pardir, os.path.pardir)
)

#
# Core Django settings
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,7 @@
 
 import git
 import sentry_sdk
+from corsheaders.defaults import default_headers as default_cors_headers
 from sentry_sdk.integrations import django, redis
 
 # NLX directory urls
@@ -152,13 +153,13 @@
     "openzaak.utils.middleware.LogHeadersMiddleware",
     "django.contrib.sessions.middleware.SessionMiddleware",
     # 'django.middleware.locale.LocaleMiddleware',
+    "corsheaders.middleware.CorsMiddleware",
     "django.middleware.common.CommonMiddleware",
     "django.middleware.csrf.CsrfViewMiddleware",
     "django.contrib.auth.middleware.AuthenticationMiddleware",
     "openzaak.components.autorisaties.middleware.AuthMiddleware",
     "django.contrib.messages.middleware.MessageMiddleware",
     "django.middleware.clickjacking.XFrameOptionsMiddleware",
-    "corsheaders.middleware.CorsMiddleware",
     "openzaak.utils.middleware.APIVersionHeaderMiddleware",
     "openzaak.utils.middleware.EnabledMiddleware",
 ]
@@ -471,19 +472,23 @@
 #
 # DJANGO-CORS-MIDDLEWARE
 #
-CORS_ORIGIN_ALLOW_ALL = True
+CORS_ALLOW_ALL_ORIGINS = config("CORS_ALLOW_ALL_ORIGINS", default=False)
+CORS_ALLOWED_ORIGINS = config("CORS_ALLOWED_ORIGINS", split=True, default=[])
+CORS_ALLOWED_ORIGIN_REGEXES = config(
+    "CORS_ALLOWED_ORIGIN_REGEXES", split=True, default=[]
+)
+# Authorization is included in default_cors_headers
 CORS_ALLOW_HEADERS = (
-    "x-requested-with",
-    "content-type",
-    "accept",
-    "origin",
-    "authorization",
-    "x-csrftoken",
-    "user-agent",
-    "accept-encoding",
-    "accept-crs",
+    list(default_cors_headers)
+    + ["accept-crs", "content-crs",]
+    + config("CORS_EXTRA_ALLOW_HEADERS", split=True, default=[])
+)
+CORS_EXPOSE_HEADERS = [
     "content-crs",
-)
+]
+# Django's SESSION_COOKIE_SAMESITE = "Lax" prevents session cookies from being sent
+# cross-domain. There is no need for these cookies to be sent, since the API itself
+# uses Bearer Authentication.
 
 #
 # DJANGO-PRIVATES -- safely serve files after authorization
```
