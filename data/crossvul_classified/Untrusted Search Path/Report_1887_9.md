# CrossVul Fix Pair: Untrusted Search Path in json
**Pair ID:** 1887_9
**Vulnerability Class:** Untrusted Search Path
**CWE:** CWE-426
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1887_9`)

## Vulnerability Information & PoC

## Description
Untrusted Search Path - This might allow attackers to execute their own programs, access unauthorized data files, or modify configuration in unexpected ways.

## Vulnerable Code
```json
Lines 1-19 of the vulnerable file.

{
	"FixedFileInfo":
	{
		"FileVersion": {
			"Major": 2,
			"Minor": 13,
			"Patch": 1,
			"Build": 0
		}
	},
	"StringFileInfo":
	{
		"FileDescription": "Git LFS",
		"LegalCopyright": "GitHub, Inc. and Git LFS contributors",
		"ProductName": "Git Large File Storage (LFS)",
		"ProductVersion": "2.13.1"
	},
	"IconPath": "script/windows-installer/git-lfs-logo.ico"
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 		"FileVersion": {
 			"Major": 2,
 			"Minor": 13,
-			"Patch": 1,
+			"Patch": 2,
 			"Build": 0
 		}
 	},
@@ -13,7 +13,7 @@
 		"FileDescription": "Git LFS",
 		"LegalCopyright": "GitHub, Inc. and Git LFS contributors",
 		"ProductName": "Git Large File Storage (LFS)",
-		"ProductVersion": "2.13.1"
+		"ProductVersion": "2.13.2"
 	},
 	"IconPath": "script/windows-installer/git-lfs-logo.ico"
 }
```
