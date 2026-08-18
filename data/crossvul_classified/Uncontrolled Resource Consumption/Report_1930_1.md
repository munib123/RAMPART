# CrossVul Fix Pair: Uncontrolled Resource Consumption in scala
**Pair ID:** 1930_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1930_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```scala
Lines 1-11 of the vulnerable file.

/*
 * Copyright 2014-2020 http4s.org
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.http4s.blaze.internal

private[blaze] object compat {
  val CollectionConverters = scala.collection.JavaConverters
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,17 @@
 /*
- * Copyright 2014-2020 http4s.org
+ * Copyright 2014 http4s.org
  *
- * SPDX-License-Identifier: Apache-2.0
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
  */
 
 package org.http4s.blaze.internal
```
