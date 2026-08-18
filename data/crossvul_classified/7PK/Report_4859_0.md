# CrossVul Fix Pair: 7PK in python
**Pair ID:** 4859_0
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4859_0`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```python
Lines 104-144 of the vulnerable file.

    app = name or request.args(0)
    if (app and os.path.exists(apath(app, r=request)) and
        (not MULTI_USER_MODE or is_manager() or
         db(db.app.name == app)(db.app.owner == auth.user.id).count())):
        return app
    session.flash = T('App does not exist or you are not authorized')
    redirect(URL('site'))


def index():
    """ Index handler """

    send = request.vars.send
    if DEMO_MODE:
        session.authorized = True
        session.last_time = t0
    if not send:
        send = URL('site')
    if session.authorized:
        redirect(send)
    elif request.vars.password:
        if verify_password(request.vars.password[:1024]):
            session.authorized = True
            login_record(True)

            if CHECK_VERSION:
                session.check_version = True
            else:
                session.check_version = False

            session.last_time = t0
            if isinstance(send, list):  # ## why does this happen?
                send = str(send[0])

            redirect(send)
        else:
            times_denied = login_record(False)
            if times_denied >= allowed_number_of_attempts:
                response.flash = \
                    T('admin disabled because too many invalid login attempts')
            elif times_denied == allowed_number_of_attempts - 1:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -121,6 +121,9 @@
         send = URL('site')
     if session.authorized:
         redirect(send)
+    elif failed_login_count() >= allowed_number_of_attempts:
+        time.sleep(2 ** allowed_number_of_attempts)
+        raise HTTP(403)
     elif request.vars.password:
         if verify_password(request.vars.password[:1024]):
             session.authorized = True
```
