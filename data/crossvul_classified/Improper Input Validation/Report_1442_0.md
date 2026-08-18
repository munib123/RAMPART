# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1442_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1442_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 478-518 of the vulnerable file.

            // TODO: maybe stop special-casing English
            if (sValue == "en") {
                pUser->SetLanguage("");
                PutModule("Language is set to English");
            } else if (mTranslations.count(sValue)) {
                pUser->SetLanguage(sValue);
                PutModule("Language = " + sValue);
            } else {
                VCString vsCodes = {"en"};
                for (const auto it : mTranslations) {
                    vsCodes.push_back(it.first);
                }
                PutModule(t_f("Supported languages: {1}")(
                    CString(", ").Join(vsCodes.begin(), vsCodes.end())));
            }
        }
#endif
#ifdef HAVE_ICU
        else if (sVar == "clientencoding") {
            pUser->SetClientEncoding(sValue);
            PutModule("ClientEncoding = " + sValue);
        }
#endif
        else
            PutModule(t_s("Error: Unknown variable"));
    }

    void GetNetwork(const CString& sLine) {
        const CString sVar = sLine.Token(1).AsLower();
        const CString sUsername = sLine.Token(2);
        const CString sNetwork = sLine.Token(3);

        CIRCNetwork* pNetwork = nullptr;
        CUser* pUser;

        if (sVar.empty()) {
            PutModule(t_s("Usage: GetNetwork <variable> [username] [network]"));
            return;
        }

        if (sUsername.empty()) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -495,7 +495,7 @@
 #ifdef HAVE_ICU
         else if (sVar == "clientencoding") {
             pUser->SetClientEncoding(sValue);
-            PutModule("ClientEncoding = " + sValue);
+            PutModule("ClientEncoding = " + pUser->GetClientEncoding());
         }
 #endif
         else
```
