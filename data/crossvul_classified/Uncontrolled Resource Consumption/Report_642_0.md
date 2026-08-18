# CrossVul Fix Pair: Uncontrolled Resource Consumption in javascript
**Pair ID:** 642_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `642_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```javascript
Lines 1-32 of the vulnerable file.

'use strict'

const Buffer = require('safe-buffer').Buffer

const crypto = require('crypto')
const Transform = require('stream').Transform

const SPEC_ALGORITHMS = ['sha256', 'sha384', 'sha512']

const BASE64_REGEX = /^[a-z0-9+/]+(?:=?=?)$/i
const SRI_REGEX = /^([^-]+)-([^?]+)([?\S*]*)$/
const STRICT_SRI_REGEX = /^([^-]+)-([A-Za-z0-9+/]+(?:=?=?))([?\x21-\x7E]*)$/
const VCHAR_REGEX = /^[\x21-\x7E]+$/

class Hash {
  get isHash () { return true }
  constructor (hash, opts) {
    const strict = !!(opts && opts.strict)
    this.source = hash.trim()
    // 3.1. Integrity metadata (called "Hash" by ssri)
    // https://w3c.github.io/webappsec-subresource-integrity/#integrity-metadata-description
    const match = this.source.match(
      strict
      ? STRICT_SRI_REGEX
      : SRI_REGEX
    )
    if (!match) { return }
    if (strict && !SPEC_ALGORITHMS.some(a => a === match[1])) { return }
    this.algorithm = match[1]
    this.digest = match[2]

    const rawOpts = match[3]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,7 +9,7 @@
 
 const BASE64_REGEX = /^[a-z0-9+/]+(?:=?=?)$/i
 const SRI_REGEX = /^([^-]+)-([^?]+)([?\S*]*)$/
-const STRICT_SRI_REGEX = /^([^-]+)-([A-Za-z0-9+/]+(?:=?=?))([?\x21-\x7E]*)$/
+const STRICT_SRI_REGEX = /^([^-]+)-([A-Za-z0-9+/=]{44,88})(\?[\x21-\x7E]*)*$/
 const VCHAR_REGEX = /^[\x21-\x7E]+$/
 
 class Hash {
```
