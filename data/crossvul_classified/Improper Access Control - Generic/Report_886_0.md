# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 886_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `886_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1583-1610 of the vulnerable file.

    bool OnFailedLogin(const CString& sUsername, const CString& sRemoteIP);
    bool OnUnknownUserRaw(CClient* pClient, CString& sLine);
    bool OnUnknownUserRawMessage(CMessage& Message);
    bool OnClientCapLs(CClient* pClient, SCString& ssCaps);
    bool IsClientCapSupported(CClient* pClient, const CString& sCap,
                              bool bState);
    bool OnClientCapRequest(CClient* pClient, const CString& sCap, bool bState);
    bool OnModuleLoading(const CString& sModName, const CString& sArgs,
                         CModInfo::EModuleType eType, bool& bSuccess,
                         CString& sRetMsg);
    bool OnModuleUnloading(CModule* pModule, bool& bSuccess, CString& sRetMsg);
    bool OnGetModInfo(CModInfo& ModInfo, const CString& sModule, bool& bSuccess,
                      CString& sRetMsg);
    bool OnGetAvailableMods(std::set<CModInfo>& ssMods,
                            CModInfo::EModuleType eType);
    // !Global Modules

  private:
    static ModHandle OpenModule(const CString& sModule, const CString& sModPath,
                                CModInfo& Info, CString& sRetMsg);

  protected:
    CUser* m_pUser;
    CIRCNetwork* m_pNetwork;
    CClient* m_pClient;
};

#endif  // !ZNC_MODULES_H
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1600,6 +1600,7 @@
   private:
     static ModHandle OpenModule(const CString& sModule, const CString& sModPath,
                                 CModInfo& Info, CString& sRetMsg);
+    static bool ValidateModuleName(const CString& sModule, CString& sRetMsg);
 
   protected:
     CUser* m_pUser;
```
