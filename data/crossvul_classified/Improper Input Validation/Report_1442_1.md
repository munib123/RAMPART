# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1442_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1442_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 1465-1505 of the vulnerable file.

    }
}

void CIRCNetwork::SetRealName(const CString& s) {
    if (m_pUser->GetRealName().Equals(s)) {
        m_sRealName = "";
    } else {
        m_sRealName = s;
    }
}

void CIRCNetwork::SetBindHost(const CString& s) {
    if (m_pUser->GetBindHost().Equals(s)) {
        m_sBindHost = "";
    } else {
        m_sBindHost = s;
    }
}

void CIRCNetwork::SetEncoding(const CString& s) {
    m_sEncoding = s;
    if (GetIRCSock()) {
        GetIRCSock()->SetEncoding(s);
    }
}

void CIRCNetwork::SetQuitMsg(const CString& s) {
    if (m_pUser->GetQuitMsg().Equals(s)) {
        m_sQuitMsg = "";
    } else {
        m_sQuitMsg = s;
    }
}

CString CIRCNetwork::ExpandString(const CString& sStr) const {
    CString sRet;
    return ExpandString(sStr, sRet);
}

CString& CIRCNetwork::ExpandString(const CString& sStr, CString& sRet) const {
    sRet = sStr;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1482,9 +1482,9 @@
 }
 
 void CIRCNetwork::SetEncoding(const CString& s) {
-    m_sEncoding = s;
+    m_sEncoding = CZNC::Get().FixupEncoding(s);
     if (GetIRCSock()) {
-        GetIRCSock()->SetEncoding(s);
+        GetIRCSock()->SetEncoding(m_sEncoding);
     }
 }
 
```
