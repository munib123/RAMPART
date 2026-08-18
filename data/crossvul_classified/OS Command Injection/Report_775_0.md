# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 775_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `775_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 1-41 of the vulnerable file.

'use strict';

const path = require('path');
const { promisify } = require('util');
const tmpDir = promisify(require('tmp').dir);
const fs = require('fs-extra');
const uuidv1 = require('uuid/v1');
const debug = require('debug')('git-diff-apply');
const utils = require('./utils');
const getRootDir = require('./get-root-dir');
const getSubDir = require('./get-sub-dir');
const gitInit = require('./git-init');
const gitStatus = require('./git-status');
const commit = require('./commit');
const checkOutTag = require('./check-out-tag');
const convertToObj = require('./convert-to-obj');
const resolveConflicts = require('./resolve-conflicts');
const commitAndTag = require('./commit-and-tag');
const gitRemoveAll = require('./git-remove-all');
const createCustomRemote = require('./create-custom-remote');

const { isGitClean } = gitStatus;
const { gitConfigInit } = gitInit;

const tempBranchName = uuidv1();

async function ensureDir(dir) {
  debug('ensureDir', dir);
  await fs.ensureDir(dir);
}

module.exports = async function gitDiffApply({
  cwd = process.cwd(),
  remoteUrl,
  startTag,
  endTag,
  resolveConflicts: _resolveConflicts,
  ignoredFiles = [],
  reset,
  init,
  createCustomDiff,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,7 @@
 const commitAndTag = require('./commit-and-tag');
 const gitRemoveAll = require('./git-remove-all');
 const createCustomRemote = require('./create-custom-remote');
+const { runWithSpawn } = require('./run');
 
 const { isGitClean } = gitStatus;
 const { gitConfigInit } = gitInit;
@@ -222,7 +223,7 @@
     _tmpDir = await tmpDir();
     tmpWorkingDir = _tmpDir;
 
-    await utils.run(`git clone ${remoteUrl} ${_tmpDir}`);
+    await runWithSpawn('git', ['clone', remoteUrl, _tmpDir]);
 
     // needed because we are going to be committing in here
     await gitConfigInit({ cwd: _tmpDir });
```
