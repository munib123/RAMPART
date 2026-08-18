# CrossVul Fix Pair: Time-of-check Time-of-use (TOCTOU) Race Condition in javascript
**Pair ID:** 1036_0
**Vulnerability Class:** Time-of-check Time-of-use (TOCTOU) Race Condition
**CWE:** CWE-367
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1036_0`)

## Vulnerability Information & PoC

## Description
Time-of-check Time-of-use (TOCTOU) Race Condition - This weakness can be security-relevant when an attacker can influence the state of the resource between check and use.

## Vulnerable Code
```javascript
Lines 1-33 of the vulnerable file.

/* @flow */

import type {FetchedMetadata, Manifest, PackageRemote} from './types.js';
import type {Fetchers} from './fetchers/index.js';
import type PackageReference from './package-reference.js';
import type Config from './config.js';
import {MessageError} from './errors.js';
import * as fetchers from './fetchers/index.js';
import * as fs from './util/fs.js';
import * as promise from './util/promise.js';

async function fetchCache(dest: string, fetcher: Fetchers, config: Config): Promise<FetchedMetadata> {
  const {hash, package: pkg} = await config.readPackageMetadata(dest);
  await fetcher.setupMirrorFromCache();
  return {
    package: pkg,
    hash,
    dest,
    cached: true,
  };
}

export async function fetchOneRemote(
  remote: PackageRemote,
  name: string,
  version: string,
  dest: string,
  config: Config,
): Promise<FetchedMetadata> {
  // Mock metadata for symlinked dependencies
  if (remote.type === 'link') {
    const mockPkg: Manifest = {_uid: '', name: '', version: '0.0.0'};
    return Promise.resolve({resolved: null, hash: '', dest, package: mockPkg, cached: false});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,8 +9,17 @@
 import * as fs from './util/fs.js';
 import * as promise from './util/promise.js';
 
-async function fetchCache(dest: string, fetcher: Fetchers, config: Config): Promise<FetchedMetadata> {
-  const {hash, package: pkg} = await config.readPackageMetadata(dest);
+const ssri = require('ssri');
+
+async function fetchCache(dest: string, fetcher: Fetchers, config: Config, integrity: ?string): Promise<FetchedMetadata> {
+  const {hash, package: pkg, remote} = await config.readPackageMetadata(dest);
+
+  if (integrity) {
+    if (!remote.integrity || !ssri.parse(integrity).match(remote.integrity)) {
+      throw new MessageError('Incorrect integrity when fetching from the cache');
+    }
+  }
+
   await fetcher.setupMirrorFromCache();
   return {
     package: pkg,
@@ -40,7 +49,7 @@
 
   const fetcher = new Fetcher(dest, remote, config);
   if (await config.isValidModuleDest(dest)) {
-    return fetchCache(dest, fetcher, config);
+      return fetchCache(dest, fetcher, config, remote.integrity);
   }
 
   // remove as the module may be invalid
```
