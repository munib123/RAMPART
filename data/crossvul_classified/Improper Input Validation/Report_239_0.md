# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 239_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `239_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 86-126 of the vulnerable file.

    }
}

void CClient::SendRequiredPasswordNotice() {
    PutClient(":irc.znc.in 464 " + GetNick() + " :Password required");
    PutClient(
        ":irc.znc.in NOTICE " + GetNick() + " :*** "
        "You need to send your password. "
        "Configure your client to send a server password.");
    PutClient(
        ":irc.znc.in NOTICE " + GetNick() + " :*** "
        "To connect now, you can use /quote PASS <username>:<password>, "
        "or /quote PASS <username>/<network>:<password> to connect to a "
        "specific network.");
}

void CClient::ReadLine(const CString& sData) {
    CLanguageScope user_lang(GetUser() ? GetUser()->GetLanguage() : "");
    CString sLine = sData;

    sLine.TrimRight("\n\r");

    DEBUG("(" << GetFullName() << ") CLI -> ZNC ["
        << CDebug::Filter(sLine) << "]");

    bool bReturn = false;
    if (IsAttached()) {
        NETWORKMODULECALL(OnUserRaw(sLine), m_pUser, m_pNetwork, this,
                          &bReturn);
    } else {
        GLOBALMODULECALL(OnUnknownUserRaw(this, sLine), &bReturn);
    }
    if (bReturn) return;

    CMessage Message(sLine);
    Message.SetClient(this);

    if (IsAttached()) {
        NETWORKMODULECALL(OnUserRawMessage(Message), m_pUser, m_pNetwork, this,
                          &bReturn);
    } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,7 +103,8 @@
     CLanguageScope user_lang(GetUser() ? GetUser()->GetLanguage() : "");
     CString sLine = sData;
 
-    sLine.TrimRight("\n\r");
+    sLine.Replace("\n", "");
+    sLine.Replace("\r", "");
 
     DEBUG("(" << GetFullName() << ") CLI -> ZNC ["
         << CDebug::Filter(sLine) << "]");
```
