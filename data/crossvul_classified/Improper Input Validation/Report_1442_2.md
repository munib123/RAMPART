# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1442_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1442_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 1236-1276 of the vulnerable file.

}

// Setters
void CUser::SetNick(const CString& s) { m_sNick = s; }
void CUser::SetAltNick(const CString& s) { m_sAltNick = s; }
void CUser::SetIdent(const CString& s) { m_sIdent = s; }
void CUser::SetRealName(const CString& s) { m_sRealName = s; }
void CUser::SetBindHost(const CString& s) { m_sBindHost = s; }
void CUser::SetDCCBindHost(const CString& s) { m_sDCCBindHost = s; }
void CUser::SetPass(const CString& s, eHashType eHash, const CString& sSalt) {
    m_sPass = s;
    m_eHashType = eHash;
    m_sPassSalt = sSalt;
}
void CUser::SetMultiClients(bool b) { m_bMultiClients = b; }
void CUser::SetDenyLoadMod(bool b) { m_bDenyLoadMod = b; }
void CUser::SetAdmin(bool b) { m_bAdmin = b; }
void CUser::SetDenySetBindHost(bool b) { m_bDenySetBindHost = b; }
void CUser::SetDefaultChanModes(const CString& s) { m_sDefaultChanModes = s; }
void CUser::SetClientEncoding(const CString& s) {
    m_sClientEncoding = s;
    for (CClient* pClient : GetAllClients()) {
        pClient->SetEncoding(s);
    }
}
void CUser::SetQuitMsg(const CString& s) { m_sQuitMsg = s; }
void CUser::SetAutoClearChanBuffer(bool b) {
    for (CIRCNetwork* pNetwork : m_vIRCNetworks) {
        for (CChan* pChan : pNetwork->GetChans()) {
            pChan->InheritAutoClearChanBuffer(b);
        }
    }
    m_bAutoClearChanBuffer = b;
}
void CUser::SetAutoClearQueryBuffer(bool b) { m_bAutoClearQueryBuffer = b; }

bool CUser::SetBufferCount(unsigned int u, bool bForce) {
    return SetChanBufferSize(u, bForce);
}

bool CUser::SetChanBufferSize(unsigned int u, bool bForce) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1253,9 +1253,9 @@
 void CUser::SetDenySetBindHost(bool b) { m_bDenySetBindHost = b; }
 void CUser::SetDefaultChanModes(const CString& s) { m_sDefaultChanModes = s; }
 void CUser::SetClientEncoding(const CString& s) {
-    m_sClientEncoding = s;
+    m_sClientEncoding = CZNC::Get().FixupEncoding(s);
     for (CClient* pClient : GetAllClients()) {
-        pClient->SetEncoding(s);
+        pClient->SetEncoding(m_sClientEncoding);
     }
 }
 void CUser::SetQuitMsg(const CString& s) { m_sQuitMsg = s; }
```
