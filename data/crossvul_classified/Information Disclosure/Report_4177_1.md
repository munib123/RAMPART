# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 4177_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4177_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 1-21 of the vulnerable file.

from rest_framework.status import HTTP_400_BAD_REQUEST
from rest_framework.views import APIView

from backend.response import FormattedResponse
from config import config
from backend.permissions import AdminOrAnonymousReadOnly


class ConfigView(APIView):
    throttle_scope = "config"
    permission_classes = (AdminOrAnonymousReadOnly,)

    def get(self, request, name=None):
        if name is None:
            if request.user.is_staff:
                return FormattedResponse(config.get_all())
            return FormattedResponse(config.get_all_non_sensitive())
        return FormattedResponse(config.get(name))

    def post(self, request, name):
        if "value" not in request.data:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-from rest_framework.status import HTTP_400_BAD_REQUEST
+from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN
 from rest_framework.views import APIView
 
 from backend.response import FormattedResponse
@@ -12,10 +12,12 @@
 
     def get(self, request, name=None):
         if name is None:
-            if request.user.is_staff:
+            if request.user.is_superuser:
                 return FormattedResponse(config.get_all())
             return FormattedResponse(config.get_all_non_sensitive())
-        return FormattedResponse(config.get(name))
+        if not config.is_sensitive(name) or request.is_superuser:
+            return FormattedResponse(config.get(name))
+        return FormattedResponse(status=HTTP_403_FORBIDDEN)
 
     def post(self, request, name):
         if "value" not in request.data:
```
