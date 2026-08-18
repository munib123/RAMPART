# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 4361_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4361_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 3-45 of the vulnerable file.

// ==================================================================================
// index.js
// ----------------------------------------------------------------------------------
// Description:   System Information - library
//                for Node.js
// Copyright:     (c) 2014 - 2020
// Author:        Sebastian Hildebrandt
// ----------------------------------------------------------------------------------
// Contributors:  Guillaume Legrain (https://github.com/glegrain)
//                Riccardo Novaglia (https://github.com/richy24)
//                Quentin Busuttil (https://github.com/Buzut)
//                Lapsio (https://github.com/lapsio)
//                csy (https://github.com/csy1983)
// ----------------------------------------------------------------------------------
// License:       MIT
// ==================================================================================

// ----------------------------------------------------------------------------------
// Dependencies
// ----------------------------------------------------------------------------------

// Object.freeze(String.prototype);
// Object.freeze(Object.prototype);

const lib_version = require('../package.json').version;
const util = require('./util');
const system = require('./system');
const osInfo = require('./osinfo');
const cpu = require('./cpu');
const memory = require('./memory');
const battery = require('./battery');
const graphics = require('./graphics');
const filesystem = require('./filesystem');
const network = require('./network');
const wifi = require('./wifi');
const processes = require('./processes');
const users = require('./users');
const internet = require('./internet');
const docker = require('./docker');
const vbox = require('./virtualbox');

let _platform = process.platform;
const _windows = (_platform === 'win32');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,9 +20,6 @@
 // ----------------------------------------------------------------------------------
 // Dependencies
 // ----------------------------------------------------------------------------------
-
-// Object.freeze(String.prototype);
-// Object.freeze(Object.prototype);
 
 const lib_version = require('../package.json').version;
 const util = require('./util');
```
