# CrossVul Fix Pair: Untrusted Search Path in cpp
**Pair ID:** 5331_0
**Vulnerability Class:** Untrusted Search Path
**CWE:** CWE-426
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5331_0`)

## Vulnerability Information & PoC

## Description
Untrusted Search Path - This might allow attackers to execute their own programs, access unauthorized data files, or modify configuration in unexpected ways.

## Vulnerable Code
```cpp
Lines 28-68 of the vulnerable file.

#include "settings.h"
#include "ui.h"
#include "error.h"

#include <wx/string.h>

#include <sstream>
#include <rpc.h>
#include <time.h>

namespace winsparkle
{

/*--------------------------------------------------------------------------*
                                  helpers
 *--------------------------------------------------------------------------*/

namespace
{

std::wstring CreateUniqueTempDirectory()
{
    // We need to put downloaded updates into a directory of their own, because
    // if we put it in $TMP, some DLLs could be there and interfere with the
    // installer.
    //
    // This code creates a new randomized directory name and tries to create it;
    // this process is repeated if the directory already exists.
    wchar_t tmpdir[MAX_PATH+1];
    if ( GetTempPath(MAX_PATH+1, tmpdir) == 0 )
        throw Win32Exception("Cannot create temporary directory");

    for ( ;; )
    {
        std::wstring dir(tmpdir);
        dir += L"Update-";

        UUID uuid;
        UuidCreate(&uuid);
        RPC_WSTR uuidStr;
        RPC_STATUS status = UuidToString(&uuid, &uuidStr);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,6 +45,17 @@
 namespace
 {
 
+std::wstring GetUniqueTempDirectoryPrefix()
+{
+    wchar_t tmpdir[MAX_PATH + 1];
+    if (GetTempPath(MAX_PATH + 1, tmpdir) == 0)
+        throw Win32Exception("Cannot create temporary directory");
+
+    std::wstring dir(tmpdir);
+    dir += L"Update-";
+    return dir;
+}
+
 std::wstring CreateUniqueTempDirectory()
 {
     // We need to put downloaded updates into a directory of their own, because
@@ -53,15 +64,11 @@
     //
     // This code creates a new randomized directory name and tries to create it;
     // this process is repeated if the directory already exists.
-    wchar_t tmpdir[MAX_PATH+1];
-    if ( GetTempPath(MAX_PATH+1, tmpdir) == 0 )
-        throw Win32Exception("Cannot create temporary directory");
+    const std::wstring tmpdir = GetUniqueTempDirectoryPrefix();
 
     for ( ;; )
     {
         std::wstring dir(tmpdir);
-        dir += L"Update-";
-
         UUID uuid;
         UuidCreate(&uuid);
         RPC_WSTR uuidStr;
@@ -192,6 +199,21 @@
     if ( !Settings::ReadConfigValue("UpdateTempDir", tmpdir) )
         return;
 
+    // Check that the directory actually is a valid update temp dir, to prevent
+    // malicious users from forcing us into deleting arbitrary directories:
+    try
+    {
+        if (tmpdir.find(GetUniqueTempDirectoryPrefix()) != 0)
+        {
+            Settings::DeleteConfigValue("UpdateTempDir");
+            return;
+        }
+    }
+    catch (Win32Exception&) // cannot determine temp directory
+    {
+        return;
+    }
+
     tmpdir.append(1, '\0'); // double NULL-terminate for SHFileOperation
 
     SHFILEOPSTRUCT fos = {0};
```
