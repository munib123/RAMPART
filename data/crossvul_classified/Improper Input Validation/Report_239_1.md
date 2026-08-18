# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 239_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `239_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 139-179 of the vulnerable file.


void CIRCSock::Quit(const CString& sQuitMsg) {
    if (IsClosed()) {
        return;
    }
    if (!m_bAuthed) {
        Close(CLT_NOW);
        return;
    }
    if (!sQuitMsg.empty()) {
        PutIRC("QUIT :" + sQuitMsg);
    } else {
        PutIRC("QUIT :" + m_pNetwork->ExpandString(m_pNetwork->GetQuitMsg()));
    }
    Close(CLT_AFTERWRITE);
}

void CIRCSock::ReadLine(const CString& sData) {
    CString sLine = sData;

    sLine.TrimRight("\n\r");

    DEBUG("(" << m_pNetwork->GetUser()->GetUserName() << "/"
              << m_pNetwork->GetName() << ") IRC -> ZNC [" << sLine << "]");

    bool bReturn = false;
    IRCSOCKMODULECALL(OnRaw(sLine), &bReturn);
    if (bReturn) return;

    CMessage Message(sLine);
    Message.SetNetwork(m_pNetwork);

    IRCSOCKMODULECALL(OnRawMessage(Message), &bReturn);
    if (bReturn) return;

    switch (Message.GetType()) {
        case CMessage::Type::Account:
            bReturn = OnAccountMessage(Message);
            break;
        case CMessage::Type::Action:
            bReturn = OnActionMessage(Message);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -156,7 +156,8 @@
 void CIRCSock::ReadLine(const CString& sData) {
     CString sLine = sData;
 
-    sLine.TrimRight("\n\r");
+    sLine.Replace("\n", "");
+    sLine.Replace("\r", "");
 
     DEBUG("(" << m_pNetwork->GetUser()->GetUserName() << "/"
               << m_pNetwork->GetName() << ") IRC -> ZNC [" << sLine << "]");
```
