# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 714_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `714_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 1-34 of the vulnerable file.

// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * Module containing util methods.
 */
const { MODEL_LOCAL_PATH, UNISON_NAME } = require('./constants');

/**
 * Returns a array containing phoneme and endtime fields.
 * Example - [{ phoneme: 'sil', endtime: 0.6278 }]
 * @param {String} festivalAlignment festival alignment string to be parsed.
 */
const getAlignmentData = (festivalAlignment) => {
  // The data is in the following pattern.
  // Example - id _22 ; name sil ; end 0.223152 ;
  try {
    const result = [];
    // Remove the alignment header and then the trailing newline.
    // eslint-disable-next-line no-param-reassign
    festivalAlignment = festivalAlignment
      .replace('()\n', '')
      .replace(/\n$/, '');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,8 @@
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
+
+const settings = require('./settings');
 
 /**
  * Module containing util methods.
@@ -87,8 +89,20 @@
   localFolder: MODEL_LOCAL_PATH,
 });
 
+/**
+ * Returns the original string with characters
+ * specified in settings replaced with spaces.
+ * @text {String} text to be replaced.
+ */
+const replaceCharactersWithSpaces = (text) => {
+  const re = new RegExp(`[${settings.CHARACTERS_TO_REPLACE_WITH_SPACES}]`, 'g');
+  const newText = text.replace(re, ' ').trim();
+  return newText;
+};
+
 module.exports = {
   getAlignmentData,
   getExecErrorMessage,
   getVoiceSettings,
+  replaceCharactersWithSpaces,
 };
```
