# CrossVul Fix Pair: Improper Authentication in python
**Pair ID:** 1224_4
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1224_4`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```python
Lines 182-222 of the vulnerable file.

            )
        else:
            form = RegistrationForm(realm_creation=realm_creation)
    else:
        postdata = request.POST.copy()
        if name_changes_disabled(realm):
            # If we populate profile information via LDAP and we have a
            # verified name from you on file, use that. Otherwise, fall
            # back to the full name in the request.
            try:
                postdata.update({'full_name': request.session['authenticated_full_name']})
                name_validated = True
            except KeyError:
                pass
        form = RegistrationForm(postdata, realm_creation=realm_creation)

    if not (password_auth_enabled(realm) and password_required):
        form['password'].field.required = False

    if form.is_valid():
        if password_auth_enabled(realm):
            password = form.cleaned_data['password']
        else:
            # SSO users don't need no passwords
            password = None

        if realm_creation:
            string_id = form.cleaned_data['realm_subdomain']
            realm_name = form.cleaned_data['realm_name']
            realm = do_create_realm(string_id, realm_name)
            setup_realm_internal_bots(realm)
        assert(realm is not None)

        full_name = form.cleaned_data['full_name']
        short_name = email_to_username(email)
        default_stream_group_names = request.POST.getlist('default_stream_group')
        default_stream_groups = lookup_default_stream_groups(default_stream_group_names, realm)

        timezone = ""
        if 'timezone' in request.POST and request.POST['timezone'] in get_all_timezones():
            timezone = request.POST['timezone']
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -199,10 +199,14 @@
         form['password'].field.required = False
 
     if form.is_valid():
-        if password_auth_enabled(realm):
+        if password_auth_enabled(realm) and form['password'].field.required:
             password = form.cleaned_data['password']
         else:
-            # SSO users don't need no passwords
+            # If the user wasn't prompted for a password when
+            # completing the authentication form (because they're
+            # signing up with SSO and no password is required), set
+            # the password field to `None` (Which causes Django to
+            # create an unusable password).
             password = None
 
         if realm_creation:
```
