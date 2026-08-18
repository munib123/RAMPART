# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in cpp
**Pair ID:** 240_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `240_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```cpp
Lines 540-580 of the vulnerable file.

        }
    }

    if (!m_bPathsSet) {
        SetPaths(pModule, true);
    }

    if (m_Template.GetFileName().empty() &&
        !m_Template.SetFile(sPageName + ".tmpl")) {
        return PAGE_NOTFOUND;
    }

    if (m_Template.PrintString(sPageRet)) {
        return PAGE_PRINT;
    } else {
        return PAGE_NOTFOUND;
    }
}

CString CWebSock::GetSkinPath(const CString& sSkinName) {
    CString sRet = CZNC::Get().GetZNCPath() + "/webskins/" + sSkinName;

    if (!CFile::IsDir(sRet)) {
        sRet = CZNC::Get().GetCurPath() + "/webskins/" + sSkinName;

        if (!CFile::IsDir(sRet)) {
            sRet = CString(_SKINDIR_) + "/" + sSkinName;
        }
    }

    return sRet + "/";
}

bool CWebSock::ForceLogin() {
    if (GetSession()->IsLoggedIn()) {
        return true;
    }

    GetSession()->AddError("You must login to view that page");
    Redirect("/");
    return false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -557,13 +557,15 @@
 }
 
 CString CWebSock::GetSkinPath(const CString& sSkinName) {
-    CString sRet = CZNC::Get().GetZNCPath() + "/webskins/" + sSkinName;
+    const CString sSkin = sSkinName.Replace_n("/", "_").Replace_n(".", "_");
+
+    CString sRet = CZNC::Get().GetZNCPath() + "/webskins/" + sSkin;
 
     if (!CFile::IsDir(sRet)) {
-        sRet = CZNC::Get().GetCurPath() + "/webskins/" + sSkinName;
+        sRet = CZNC::Get().GetCurPath() + "/webskins/" + sSkin;
 
         if (!CFile::IsDir(sRet)) {
-            sRet = CString(_SKINDIR_) + "/" + sSkinName;
+            sRet = CString(_SKINDIR_) + "/" + sSkin;
         }
     }
 
```
