# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in go
**Pair ID:** 4388_2
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4388_2`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```go
Lines 1-26 of the vulnerable file.

// DBDeployer - The MySQL Sandbox
// Copyright © 2006-2020 Giuseppe Maxia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

// This file was generated during build. Do not edit.
// Build time: 2020-12-14 16:00

var VersionDef string = "1.58.1" // 2020-12-14

// Compatible version is the version used to mark compatible archives (templates, configuration).
// It is usually major.minor.0, except when we are at version 0.x, when
// every revision may bring incompatibility
var CompatibleVersion string = "1.58.0" // 2020-12-11
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,9 +16,9 @@
 package common
 
 // This file was generated during build. Do not edit.
-// Build time: 2020-12-14 16:00
+// Build time: 2020-12-15 10:49
 
-var VersionDef string = "1.58.1" // 2020-12-14
+var VersionDef string = "1.58.2" // 2020-12-15
 
 // Compatible version is the version used to mark compatible archives (templates, configuration).
 // It is usually major.minor.0, except when we are at version 0.x, when
```
