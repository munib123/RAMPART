# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in javascript
**Pair ID:** 774_7
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `774_7`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```javascript
Lines 1-25 of the vulnerable file.

/* @flow */

import {MANIFEST_FIELDS} from '../../constants';
import type {Reporter} from '../../reporters/index.js';
import {isValidLicense} from './util.js';
import {normalizePerson, extractDescription} from './util.js';
import {hostedGitFragmentToGitUrl} from '../../resolvers/index.js';
import inferLicense from './infer-license.js';
import * as fs from '../fs.js';

const semver = require('semver');
const path = require('path');
const url = require('url');

const LICENSE_RENAMES: {[key: string]: ?string} = {
  'MIT/X11': 'MIT',
  X11: 'MIT',
};

type Dict<T> = {
  [key: string]: T,
};

type WarnFunction = (msg: string) => void;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
 
 import {MANIFEST_FIELDS} from '../../constants';
 import type {Reporter} from '../../reporters/index.js';
-import {isValidLicense} from './util.js';
+import {isValidBin, isValidLicense} from './util.js';
 import {normalizePerson, extractDescription} from './util.js';
 import {hostedGitFragmentToGitUrl} from '../../resolvers/index.js';
 import inferLicense from './infer-license.js';
@@ -11,6 +11,8 @@
 const semver = require('semver');
 const path = require('path');
 const url = require('url');
+
+const VALID_BIN_KEYS = /^[a-z0-9_-]+$/i;
 
 const LICENSE_RENAMES: {[key: string]: ?string} = {
   'MIT/X11': 'MIT',
@@ -157,6 +159,24 @@
     // Remove scoped package name for consistency with NPM's bin field fixing behaviour
     const name = info.name.replace(/^@[^\/]+\//, '');
     info.bin = {[name]: info.bin};
+  }
+
+  // Validate that the bin entries reference only files within their package, and that
+  // their name is a valid file name
+  if (typeof info.bin === 'object' && info.bin !== null) {
+    const bin: Object = info.bin;
+    for (const key of Object.keys(bin)) {
+      const target = bin[key];
+      if (!VALID_BIN_KEYS.test(key) || !isValidBin(target)) {
+        delete bin[key];
+        warn(reporter.lang('invalidBinEntry', info.name, key));
+      } else {
+        bin[key] = path.normalize(target);
+      }
+    }
+  } else if (typeof info.bin !== 'undefined') {
+    delete info.bin;
+    warn(reporter.lang('invalidBinField', info.name));
   }
 
   // bundleDependencies is an alias for bundledDependencies
```
