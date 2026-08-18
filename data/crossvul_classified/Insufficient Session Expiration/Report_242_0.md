# CrossVul Fix Pair: Insufficient Session Expiration in cpp
**Pair ID:** 242_0
**Vulnerability Class:** Insufficient Session Expiration
**CWE:** CWE-613
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `242_0`)

## Vulnerability Information & PoC

## Description
Insufficient Session Expiration - According to WASC, Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs for authorization.

## Vulnerable Code
```cpp
Lines 322-362 of the vulnerable file.

        env.insert(QStringLiteral("XDG_SESSION_PATH"), daemonApp->displayManager()->sessionPath(QStringLiteral("Session%1").arg(daemonApp->newSessionId())));
        env.insert(QStringLiteral("DESKTOP_SESSION"), session.desktopSession());
        env.insert(QStringLiteral("XDG_CURRENT_DESKTOP"), session.desktopNames());
        env.insert(QStringLiteral("XDG_SESSION_CLASS"), QStringLiteral("user"));
        env.insert(QStringLiteral("XDG_SESSION_TYPE"), session.xdgSessionType());
        env.insert(QStringLiteral("XDG_SEAT"), seat()->name());

        env.insert(QStringLiteral("XDG_SESSION_DESKTOP"), session.desktopNames());
        if (seat()->name() == QLatin1String("seat0")) {
            env.insert(QStringLiteral("XDG_VTNR"), QString::number(vt));
        }

        m_auth->insertEnvironment(env);

        m_auth->setUser(user);
        if (existingSessionId.isNull()) {
            m_auth->setSession(session.exec());
        } else {
            //we only want to unlock the session if we can lock in, so we want to go via PAM auth, but not start a new session
            //by not setting the session and the helper will emit authentication and then quit
            connect(m_auth, &Auth::authentication, this, [=](){
                qDebug() << "activating existing seat";
                OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(), Logind::managerPath(), QDBusConnection::systemBus());
                manager.UnlockSession(existingSessionId);
                manager.ActivateSession(existingSessionId);
            });
        }
        m_auth->start();
    }

    void Display::slotAuthenticationFinished(const QString &user, bool success) {
        if (success) {
            qDebug() << "Authenticated successfully";

            m_auth->setCookie(qobject_cast<XorgDisplayServer *>(m_displayServer)->cookie());

            // save last user and last session
            if (mainConfig.Users.RememberLastUser.get())
                stateConfig.Last.User.set(m_auth->user());
            else
                stateConfig.Last.User.setDefault();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -339,7 +339,9 @@
         } else {
             //we only want to unlock the session if we can lock in, so we want to go via PAM auth, but not start a new session
             //by not setting the session and the helper will emit authentication and then quit
-            connect(m_auth, &Auth::authentication, this, [=](){
+            connect(m_auth, &Auth::authentication, this, [=](const QString &, bool success){
+                if(!success)
+                    return;
                 qDebug() << "activating existing seat";
                 OrgFreedesktopLogin1ManagerInterface manager(Logind::serviceName(), Logind::managerPath(), QDBusConnection::systemBus());
                 manager.UnlockSession(existingSessionId);
```
