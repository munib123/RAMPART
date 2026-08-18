# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in python
**Pair ID:** 1892_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1892_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```python
Lines 164-205 of the vulnerable file.

        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(MultiDict([]), meta=suppress_form_csrf())
    else:
        form = form_class(request.form, meta=suppress_form_csrf())

    if form.validate_on_submit():
        remember_me = form.remember.data if "remember" in form else None
        if config_value("TWO_FACTOR") and (
            config_value("TWO_FACTOR_REQUIRED")
            or (form.user.tf_totp_secret and form.user.tf_primary_method)
        ):
            return tf_login(
                form.user, remember=remember_me, primary_authn_via="password"
            )

        login_user(form.user, remember=remember_me, authn_via=["password"])
        after_this_request(_commit)

        if not _security._want_json(request):
            return redirect(get_post_login_redirect())

    if _security._want_json(request):
        if current_user.is_authenticated:
            form.user = current_user
        return base_render_json(form, include_auth_token=True)

    if current_user.is_authenticated:
        return redirect(get_url(_security.post_login_view))
    else:
        return _security.render_template(
            config_value("LOGIN_USER_TEMPLATE"), login_user_form=form, **_ctx("login")
        )


@auth_required()
def verify():
    """View function which handles a authentication verification request.
    """
    form_class = _security.verify_form

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -181,13 +181,14 @@
         login_user(form.user, remember=remember_me, authn_via=["password"])
         after_this_request(_commit)
 
-        if not _security._want_json(request):
-            return redirect(get_post_login_redirect())
+        if _security._want_json(request):
+            return base_render_json(form, include_auth_token=True)
+        return redirect(get_post_login_redirect())
 
     if _security._want_json(request):
         if current_user.is_authenticated:
             form.user = current_user
-        return base_render_json(form, include_auth_token=True)
+        return base_render_json(form)
 
     if current_user.is_authenticated:
         return redirect(get_url(_security.post_login_view))
@@ -622,16 +623,18 @@
     if form.validate_on_submit():
         after_this_request(_commit)
         change_user_password(current_user._get_current_object(), form.new_password.data)
-        if not _security._want_json(request):
-            do_flash(*get_message("PASSWORD_CHANGE"))
-            return redirect(
-                get_url(_security.post_change_view)
-                or get_url(_security.post_login_view)
-            )
+        if _security._want_json(request):
+            form.user = current_user
+            return base_render_json(form, include_auth_token=True)
+
+        do_flash(*get_message("PASSWORD_CHANGE"))
+        return redirect(
+            get_url(_security.post_change_view) or get_url(_security.post_login_view)
+        )
 
     if _security._want_json(request):
         form.user = current_user
-        return base_render_json(form, include_auth_token=True)
+        return base_render_json(form)
 
     return _security.render_template(
         config_value("CHANGE_PASSWORD_TEMPLATE"),
```
