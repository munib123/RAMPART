# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3033_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3033_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-21 of the vulnerable file.

'use strict';

const datastore = require('@google-cloud/datastore')();

class Cache {
  async clearCache() {
    const query = datastore.createQuery('Page');
    const data = await datastore.runQuery(query);
    const entities = data[0];
    const entityKeys = entities.map((entity) => entity[datastore.KEY]);
    console.log(`Removing ${entities.length} items from the cache`);
    await datastore.delete(entityKeys);
    // TODO(samli): check info (data[1]) and loop through pages of entities to delete.
  }

  async cacheContent(key, headers, payload) {
    // Set cache length to 1 day.
    const cacheDurationMinutes = 60*24;
    const now = new Date();
    const entity = {
      key: key,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,19 @@
+/*
+ * Copyright 2017 Google Inc. All rights reserved.
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License"); you may not
+ * use this file except in compliance with the License. You may obtain a copy of
+ * the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+ * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+ * License for the specific language governing permissions and limitations under
+ * the License.
+ */
+
 'use strict';
 
 const datastore = require('@google-cloud/datastore')();
```
