# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 238_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `238_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 157-192 of the vulnerable file.

        CString sNameLower = sName.AsLower();
        pActiveConfig->m_ConfigEntries[sNameLower].push_back(sValue);
    }

    if (bCommented) ERROR("Comment not closed at end of file.");

    if (!ConfigStack.empty()) {
        const CString& sTag = ConfigStack.top().sTag;
        ERROR(
            "Not all tags are closed at the end of the file. Inner-most open "
            "tag is \""
            << sTag << "\".");
    }

    return true;
}

void CConfig::Write(CFile& File, unsigned int iIndentation) {
    CString sIndentation = CString(iIndentation, '\t');

    for (const auto& it : m_ConfigEntries) {
        for (const CString& sValue : it.second) {
            File.Write(sIndentation + it.first + " = " + sValue + "\n");
        }
    }

    for (const auto& it : m_SubConfigs) {
        for (const auto& it2 : it.second) {
            File.Write("\n");

            File.Write(sIndentation + "<" + it.first + " " + it2.first + ">\n");
            it2.second.m_pSubConfig->Write(File, iIndentation + 1);
            File.Write(sIndentation + "</" + it.first + ">\n");
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -174,9 +174,14 @@
 void CConfig::Write(CFile& File, unsigned int iIndentation) {
     CString sIndentation = CString(iIndentation, '\t');
 
+    auto SingleLine = [](const CString& s) {
+        return s.Replace_n("\r", "").Replace_n("\n", "");
+    };
+
     for (const auto& it : m_ConfigEntries) {
         for (const CString& sValue : it.second) {
-            File.Write(sIndentation + it.first + " = " + sValue + "\n");
+            File.Write(SingleLine(sIndentation + it.first + " = " + sValue) +
+                       "\n");
         }
     }
 
@@ -184,9 +189,11 @@
         for (const auto& it2 : it.second) {
             File.Write("\n");
 
-            File.Write(sIndentation + "<" + it.first + " " + it2.first + ">\n");
+            File.Write(SingleLine(sIndentation + "<" + it.first + " " +
+                                  it2.first + ">") +
+                       "\n");
             it2.second.m_pSubConfig->Write(File, iIndentation + 1);
-            File.Write(sIndentation + "</" + it.first + ">\n");
+            File.Write(SingleLine(sIndentation + "</" + it.first + ">") + "\n");
         }
     }
 }
```
