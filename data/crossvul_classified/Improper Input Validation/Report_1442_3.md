# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1442_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1442_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 2075-2117 of the vulnerable file.


    if (m_pConnectQueueTimer) {
        m_pConnectQueueTimer->Pause();
    }
}

void CZNC::ResumeConnectQueue() {
    DEBUG("Connection queue resumed");
    m_uiConnectPaused--;

    EnableConnectQueue();
    if (m_pConnectQueueTimer) {
        m_pConnectQueueTimer->UnPause();
    }
}

void CZNC::ForceEncoding() {
    m_uiForceEncoding++;
#ifdef HAVE_ICU
    for (Csock* pSock : GetManager()) {
        if (pSock->GetEncoding().empty()) {
            pSock->SetEncoding("UTF-8");
        }
    }
#endif
}
void CZNC::UnforceEncoding() { m_uiForceEncoding--; }
bool CZNC::IsForcingEncoding() const { return m_uiForceEncoding; }
CString CZNC::FixupEncoding(const CString& sEncoding) const {
    if (sEncoding.empty() && m_uiForceEncoding) {
        return "UTF-8";
    }
    return sEncoding;
}

void CZNC::AddNetworkToQueue(CIRCNetwork* pNetwork) {
    // Make sure we are not already in the queue
    if (std::find(m_lpConnectQueue.begin(), m_lpConnectQueue.end(), pNetwork) !=
        m_lpConnectQueue.end()) {
        return;
    }

    m_lpConnectQueue.push_back(pNetwork);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2092,18 +2092,36 @@
     m_uiForceEncoding++;
 #ifdef HAVE_ICU
     for (Csock* pSock : GetManager()) {
-        if (pSock->GetEncoding().empty()) {
-            pSock->SetEncoding("UTF-8");
-        }
+        pSock->SetEncoding(FixupEncoding(pSock->GetEncoding()));
     }
 #endif
 }
 void CZNC::UnforceEncoding() { m_uiForceEncoding--; }
 bool CZNC::IsForcingEncoding() const { return m_uiForceEncoding; }
 CString CZNC::FixupEncoding(const CString& sEncoding) const {
-    if (sEncoding.empty() && m_uiForceEncoding) {
+    if (!m_uiForceEncoding) {
+        return sEncoding;
+    }
+    if (sEncoding.empty()) {
         return "UTF-8";
     }
+    const char* sRealEncoding = sEncoding.c_str();
+    if (sEncoding[0] == '*' || sEncoding[0] == '^') {
+        sRealEncoding++;
+    }
+    if (!*sRealEncoding) {
+        return "UTF-8";
+    }
+#ifdef HAVE_ICU
+    UErrorCode e = U_ZERO_ERROR;
+    UConverter* cnv = ucnv_open(sRealEncoding, &e);
+    if (cnv) {
+        ucnv_close(cnv);
+    }
+    if (U_FAILURE(e)) {
+        return "UTF-8";
+    }
+#endif
     return sEncoding;
 }
 
```
