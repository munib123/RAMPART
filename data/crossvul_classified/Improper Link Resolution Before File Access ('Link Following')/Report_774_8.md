# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in javascript
**Pair ID:** 774_8
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `774_8`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```javascript
Lines 1-25 of the vulnerable file.

/* @flow */

import type {PersonObject} from '../../types.js';

const validateLicense = require('validate-npm-package-license');

export function isValidLicense(license: string): boolean {
  return !!license && validateLicense(license).validForNewPackages;
}

export function stringifyPerson(person: mixed): any {
  if (!person || typeof person !== 'object') {
    return person;
  }

  const parts = [];
  if (person.name) {
    parts.push(person.name);
  }

  const email = person.email || person.mail;
  if (typeof email === 'string') {
    parts.push(`<${email}>`);
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,10 +2,17 @@
 
 import type {PersonObject} from '../../types.js';
 
+const path = require('path');
 const validateLicense = require('validate-npm-package-license');
+
+const PARENT_PATH = /^\.\.([\\\/]|$)/;
 
 export function isValidLicense(license: string): boolean {
   return !!license && validateLicense(license).validForNewPackages;
+}
+
+export function isValidBin(bin: string): boolean {
+  return !path.isAbsolute(bin) && !PARENT_PATH.test(path.normalize(bin));
 }
 
 export function stringifyPerson(person: mixed): any {
```
