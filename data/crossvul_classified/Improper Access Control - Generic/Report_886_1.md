# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in cpp
**Pair ID:** 886_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `886_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```cpp
Lines 1607-1647 of the vulnerable file.

                            bool& bSuccess, CString& sRetMsg) {
    MODHALTCHK(OnGetModInfo(ModInfo, sModule, bSuccess, sRetMsg));
}

bool CModules::OnGetAvailableMods(set<CModInfo>& ssMods,
                                  CModInfo::EModuleType eType) {
    MODUNLOADCHK(OnGetAvailableMods(ssMods, eType));
    return false;
}

CModule* CModules::FindModule(const CString& sModule) const {
    for (CModule* pMod : *this) {
        if (sModule.Equals(pMod->GetModName())) {
            return pMod;
        }
    }

    return nullptr;
}

bool CModules::LoadModule(const CString& sModule, const CString& sArgs,
                          CModInfo::EModuleType eType, CUser* pUser,
                          CIRCNetwork* pNetwork, CString& sRetMsg) {
    sRetMsg = "";

    if (FindModule(sModule) != nullptr) {
        sRetMsg = t_f("Module {1} already loaded.")(sModule);
        return false;
    }

    bool bSuccess;
    bool bHandled = false;
    _GLOBALMODULECALL(OnModuleLoading(sModule, sArgs, eType, bSuccess, sRetMsg),
                      pUser, pNetwork, nullptr, &bHandled);
    if (bHandled) return bSuccess;

    CString sModPath, sDataPath;
    CModInfo Info;

    if (!FindModPath(sModule, sModPath, sDataPath)) {
        sRetMsg = t_f("Unable to find module {1}")(sModule);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1624,10 +1624,29 @@
     return nullptr;
 }
 
+bool CModules::ValidateModuleName(const CString& sModule, CString& sRetMsg) {
+    for (unsigned int a = 0; a < sModule.length(); a++) {
+        if (((sModule[a] < '0') || (sModule[a] > '9')) &&
+            ((sModule[a] < 'a') || (sModule[a] > 'z')) &&
+            ((sModule[a] < 'A') || (sModule[a] > 'Z')) && (sModule[a] != '_')) {
+            sRetMsg =
+                t_f("Module names can only contain letters, numbers and "
+                    "underscores, [{1}] is invalid")(sModule);
+            return false;
+        }
+    }
+
+    return true;
+}
+
 bool CModules::LoadModule(const CString& sModule, const CString& sArgs,
                           CModInfo::EModuleType eType, CUser* pUser,
                           CIRCNetwork* pNetwork, CString& sRetMsg) {
     sRetMsg = "";
+
+    if (!ValidateModuleName(sModule, sRetMsg)) {
+        return false;
+    }
 
     if (FindModule(sModule) != nullptr) {
         sRetMsg = t_f("Module {1} already loaded.")(sModule);
@@ -1781,6 +1800,10 @@
 
 bool CModules::GetModInfo(CModInfo& ModInfo, const CString& sModule,
                           CString& sRetMsg) {
+    if (!ValidateModuleName(sModule, sRetMsg)) {
+        return false;
+    }
+
     CString sModPath, sTmp;
 
     bool bSuccess;
@@ -1799,6 +1822,10 @@
 
 bool CModules::GetModPathInfo(CModInfo& ModInfo, const CString& sModule,
                               const CString& sModPath, CString& sRetMsg) {
+    if (!ValidateModuleName(sModule, sRetMsg)) {
+        return false;
+    }
+
     ModInfo.SetName(sModule);
     ModInfo.SetPath(sModPath);
 
@@ -1911,15 +1938,8 @@
     // Some sane defaults in case anything errors out below
     sRetMsg.clear();
 
-    for (unsigned int a = 0; a < sModule.length(); a++) {
-        if (((sModule[a] < '0') || (sModule[a] > '9')) &&
-            ((sModule[a] < 'a') || (sModule[a] > 'z')) &&
-            ((sModule[a] < 'A') || (sModule[a] > 'Z')) && (sModule[a] != '_')) {
-            sRetMsg =
-                t_f("Module names can only contain letters, numbers and "
-                    "underscores, [{1}] is invalid")(sModule);
-            return nullptr;
-        }
+    if (!ValidateModuleName(sModule, sRetMsg)) {
+        return nullptr;
     }
 
     // The second argument to dlopen() has a long history. It seems clear
```
