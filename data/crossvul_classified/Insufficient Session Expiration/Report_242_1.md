# CrossVul Fix Pair: Insufficient Session Expiration in cpp
**Pair ID:** 242_1
**Vulnerability Class:** Insufficient Session Expiration
**CWE:** CWE-613
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `242_1`)

## Vulnerability Information & PoC

## Description
Insufficient Session Expiration - According to WASC, Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs for authorization.

## Vulnerable Code
```cpp
Lines 202-243 of the vulnerable file.



    PamBackend::PamBackend(HelperApp *parent)
            : Backend(parent)
            , m_data(new PamData())
            , m_pam(new PamHandle(this)) {
    }

    PamBackend::~PamBackend() {
        delete m_data;
        delete m_pam;
    }

    bool PamBackend::start(const QString &user) {
        bool result;

        QString service = QStringLiteral("sddm");

        if (user == QStringLiteral("sddm") && m_greeter)
            service = QStringLiteral("sddm-greeter");
        else if (m_app->session()->path().isEmpty())
            service = QStringLiteral("sddm-check");
        else if (m_autologin)
            service = QStringLiteral("sddm-autologin");
        result = m_pam->start(service, user);

        if (!result)
            m_app->error(m_pam->errorString(), Auth::ERROR_INTERNAL);

        return result;
    }

    bool PamBackend::authenticate() {
        if (!m_pam->authenticate()) {
            m_app->error(m_pam->errorString(), Auth::ERROR_AUTHENTICATION);
            return false;
        }
        if (!m_pam->acctMgmt()) {
            m_app->error(m_pam->errorString(), Auth::ERROR_AUTHENTICATION);
            return false;
        }
        return true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -219,8 +219,6 @@
 
         if (user == QStringLiteral("sddm") && m_greeter)
             service = QStringLiteral("sddm-greeter");
-        else if (m_app->session()->path().isEmpty())
-            service = QStringLiteral("sddm-check");
         else if (m_autologin)
             service = QStringLiteral("sddm-autologin");
         result = m_pam->start(service, user);
```
