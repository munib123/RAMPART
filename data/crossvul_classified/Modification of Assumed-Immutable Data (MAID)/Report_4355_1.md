# CrossVul Fix Pair: Modification of Assumed-Immutable Data (MAID) in javascript
**Pair ID:** 4355_1
**Vulnerability Class:** Modification of Assumed-Immutable Data (MAID)
**CWE:** CWE-471
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4355_1`)

## Vulnerability Information & PoC

## Description
Modification of Assumed-Immutable Data (MAID) - This occurs when a particular input is critical enough to the functioning of the application that it should not be modifiable at all, but it is.

## Vulnerable Code
```javascript
Lines 12-52 of the vulnerable file.

import { compileLanguage } from './lib/mode_compiler.js';
import * as packageJSON from '../package.json';

const escape = utils.escapeHTML;
const inherit = utils.inherit;

const { nodeStream, mergeStreams } = utils;
const NO_MATCH = Symbol("nomatch");

/**
 * @param {any} hljs - object that is extended (legacy)
 * @returns {HLJSApi}
 */
const HLJS = function(hljs) {
  // Convenience variables for build-in objects
  /** @type {unknown[]} */
  var ArrayProto = [];

  // Global internal variables used within the highlight.js library.
  /** @type {Record<string, Language>} */
  var languages = {};
  /** @type {Record<string, string>} */
  var aliases = {};
  /** @type {HLJSPlugin[]} */
  var plugins = [];

  // safe/production mode - swallows more errors, tries to keep running
  // even if a single syntax or parse hits a fatal error
  var SAFE_MODE = true;
  var fixMarkupRe = /(^(<[^>]+>|\t|)+|\n)/gm;
  var LANGUAGE_NOT_FOUND = "Could not find the language '{}', did you forget to load/include a language module?";
  /** @type {Language} */
  const PLAINTEXT_LANGUAGE = { disableAutodetect: true, name: 'Plain text', contains: [] };

  // Global options used when within external APIs. This is modified when
  // calling the `hljs.configure` function.
  /** @type HLJSOptions */
  var options = {
    noHighlightRe: /^(no-?highlight)$/i,
    languageDetectRe: /\blang(?:uage)?-([\w-]+)\b/i,
    classPrefix: 'hljs-',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,9 +29,9 @@
 
   // Global internal variables used within the highlight.js library.
   /** @type {Record<string, Language>} */
-  var languages = {};
+  var languages = Object.create(null);
   /** @type {Record<string, string>} */
-  var aliases = {};
+  var aliases = Object.create(null);
   /** @type {HLJSPlugin[]} */
   var plugins = [];
 
```
