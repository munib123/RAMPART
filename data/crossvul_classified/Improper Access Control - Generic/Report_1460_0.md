# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in cpp
**Pair ID:** 1460_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1460_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```cpp
Lines 128-168 of the vulnerable file.

            insertEnvironmentList({QStringLiteral("LANG"), QStringLiteral("LANGUAGE"),
                                   QStringLiteral("LC_CTYPE"), QStringLiteral("LC_NUMERIC"), QStringLiteral("LC_TIME"), QStringLiteral("LC_COLLATE"),
                                   QStringLiteral("LC_MONETARY"), QStringLiteral("LC_MESSAGES"), QStringLiteral("LC_PAPER"), QStringLiteral("LC_NAME"),
                                   QStringLiteral("LC_ADDRESS"), QStringLiteral("LC_TELEPHONE"), QStringLiteral("LC_MEASUREMENT"), QStringLiteral("LC_IDENTIFICATION"),
                                   QStringLiteral("LD_LIBRARY_PATH"),
                                   QStringLiteral("QML2_IMPORT_PATH"),
                                   QStringLiteral("QT_PLUGIN_PATH"),
                                   QStringLiteral("XDG_DATA_DIRS")
            }, sysenv, env);

            env.insert(QStringLiteral("PATH"), mainConfig.Users.DefaultPath.get());
            env.insert(QStringLiteral("DISPLAY"), m_display->name());
            env.insert(QStringLiteral("XAUTHORITY"), m_authPath);
            env.insert(QStringLiteral("XCURSOR_THEME"), mainConfig.Theme.CursorTheme.get());
            env.insert(QStringLiteral("XDG_SEAT"), m_display->seat()->name());
            env.insert(QStringLiteral("XDG_SEAT_PATH"), daemonApp->displayManager()->seatPath(m_display->seat()->name()));
            env.insert(QStringLiteral("XDG_SESSION_PATH"), daemonApp->displayManager()->sessionPath(QStringLiteral("Session%1").arg(daemonApp->newSessionId())));
            env.insert(QStringLiteral("XDG_VTNR"), QString::number(m_display->terminalId()));
            env.insert(QStringLiteral("XDG_SESSION_CLASS"), QStringLiteral("greeter"));
            env.insert(QStringLiteral("XDG_SESSION_TYPE"), m_display->sessionType());
            m_auth->insertEnvironment(env);

            // log message
            qDebug() << "Greeter starting...";

            // start greeter
            m_auth->setUser(QStringLiteral("sddm"));
            m_auth->setGreeter(true);
            m_auth->setSession(args.join(QLatin1Char(' ')));
            m_auth->start();
        }

        // return success
        return true;
    }

    void Greeter::insertEnvironmentList(QStringList names, QProcessEnvironment sourceEnv, QProcessEnvironment &targetEnv) {
        for (QStringList::const_iterator it = names.constBegin(); it != names.constEnd(); ++it)
            if (sourceEnv.contains(*it))
                targetEnv.insert(*it, sourceEnv.value(*it));
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -145,6 +145,10 @@
             env.insert(QStringLiteral("XDG_VTNR"), QString::number(m_display->terminalId()));
             env.insert(QStringLiteral("XDG_SESSION_CLASS"), QStringLiteral("greeter"));
             env.insert(QStringLiteral("XDG_SESSION_TYPE"), m_display->sessionType());
+
+            //some themes may use KDE components and that will automatically load KDE's crash handler which we don't want
+            //counterintuitively setting this env disables that handler
+            env.insert(QStringLiteral("KDE_DEBUG"), QStringLiteral("1"));
             m_auth->insertEnvironment(env);
 
             // log message
```
