# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 3768_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3768_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 2-25 of the vulnerable file.

from django.contrib.auth.urls import urlpatterns
from django.contrib.auth.views import password_reset
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.template import Template, RequestContext
from django.views.decorators.cache import never_cache

@never_cache
def remote_user_auth_view(request):
    "Dummy view for remote user tests"
    t = Template("Username is {{ user }}.")
    c = RequestContext(request, {})
    return HttpResponse(t.render(c))

# special urls for auth test cases
urlpatterns = urlpatterns + patterns('',
    (r'^logout/custom_query/$', 'django.contrib.auth.views.logout', dict(redirect_field_name='follow')),
    (r'^logout/next_page/$', 'django.contrib.auth.views.logout', dict(next_page='/somewhere/')),
    (r'^remote_user/$', remote_user_auth_view),
    (r'^password_reset_from_email/$', 'django.contrib.auth.views.password_reset', dict(from_email='staffmember@example.com')),
    (r'^login_required/$', login_required(password_reset)),
    (r'^login_required_login_url/$', login_required(password_reset, login_url='/somewhere/')),
)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
     (r'^logout/next_page/$', 'django.contrib.auth.views.logout', dict(next_page='/somewhere/')),
     (r'^remote_user/$', remote_user_auth_view),
     (r'^password_reset_from_email/$', 'django.contrib.auth.views.password_reset', dict(from_email='staffmember@example.com')),
+    (r'^admin_password_reset/$', 'django.contrib.auth.views.password_reset', dict(is_admin_site=True)),
     (r'^login_required/$', login_required(password_reset)),
     (r'^login_required_login_url/$', login_required(password_reset, login_url='/somewhere/')),
 )
```
