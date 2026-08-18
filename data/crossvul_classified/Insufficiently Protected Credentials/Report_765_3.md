# CrossVul Fix Pair: Insufficiently Protected Credentials in python
**Pair ID:** 765_3
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `765_3`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```python
Lines 44-84 of the vulnerable file.

                code='inactive',
            )

        self.cleaned_data['user'] = user

        return username

    def save(self, request, login_code_url='login_code', domain_override=None, extra_context=None):
        login_code = models.LoginCode.create_code_for_user(
            user=self.cleaned_data['user'],
            next=self.cleaned_data['next'],
        )

        if not domain_override:
            current_site = get_current_site(request)
            site_name = current_site.name
            domain = current_site.domain
        else:
            site_name = domain = domain_override

        url = '{}://{}{}?code={}'.format(
            'https' if request.is_secure() else 'http',
            domain,
            resolve_url(login_code_url),
            login_code.code,
        )

        context = {
            'domain': domain,
            'site_name': site_name,
            'code': login_code.code,
            'url': url,
        }

        if extra_context:
            context.update(extra_context)

        self.send_login_code(login_code, context)

        return login_code

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,10 +61,11 @@
         else:
             site_name = domain = domain_override
 
-        url = '{}://{}{}?code={}'.format(
+        url = '{}://{}{}?user={}&code={}'.format(
             'https' if request.is_secure() else 'http',
             domain,
             resolve_url(login_code_url),
+            login_code.user.pk,
             login_code.code,
         )
 
@@ -95,11 +96,9 @@
 
 
 class LoginCodeForm(forms.Form):
-    code = forms.ModelChoiceField(
+    user = forms.CharField()
+    code = forms.CharField(
         label=_('Login code'),
-        queryset=models.LoginCode.objects.select_related('user'),
-        to_field_name='code',
-        widget=forms.TextInput,
         error_messages={
             'invalid_choice': _('Login code is invalid. It might have expired.'),
         },
@@ -114,12 +113,19 @@
 
         self.request = request
 
-    def clean_code(self):
+    def clean(self):
+        user_id = self.cleaned_data.get('user', None)
+        if user_id is None:
+            raise forms.ValidationError(
+                self.error_messages['invalid_code'],
+                code='invalid_code',
+            )
+
+        user = get_user_model().objects.get(pk=user_id)
         code = self.cleaned_data['code']
-        username = code.user.get_username()
         user = authenticate(self.request, **{
-            get_user_model().USERNAME_FIELD: username,
-            'code': code.code,
+            get_user_model().USERNAME_FIELD: user.username,
+            'code': code,
         })
 
         if not user:
@@ -130,10 +136,11 @@
 
         self.cleaned_data['user'] = user
 
-        return code
+        return self.cleaned_data
 
     def get_user(self):
         return self.cleaned_data.get('user')
 
     def save(self):
-        self.cleaned_data['code'].delete()
+        if self.get_user().login_code:
+            self.get_user().login_code.delete()
```
