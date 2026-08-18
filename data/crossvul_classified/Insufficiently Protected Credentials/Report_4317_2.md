# CrossVul Fix Pair: Insufficiently Protected Credentials in typescript
**Pair ID:** 4317_2
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4317_2`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```typescript
Lines 1-15 of the vulnerable file.

/*
 * Copyright 2020 The NATS Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
export * from "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-8/nats-base-client/internal_mod.ts";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,4 +12,4 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-export * from "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-8/nats-base-client/internal_mod.ts";
+export * from "https://raw.githubusercontent.com/nats-io/nats.deno/v1.0.0-9/nats-base-client/internal_mod.ts";
```
