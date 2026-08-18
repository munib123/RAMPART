# CrossVul Fix Pair: Uncontrolled Resource Consumption in typescript
**Pair ID:** 4633_5
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4633_5`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```typescript
Lines 1-21 of the vulnerable file.

import {JsonMapper} from "../decorators/jsonMapper";
import {JsonMapperCtx, JsonMapperMethods} from "../interfaces/JsonMapperMethods";

/**
 * Converter component for the `Set` Type.
 * @converters
 * @jsonmapper
 * @component
 */
@JsonMapper(Set)
export class SetMapper implements JsonMapperMethods {
  deserialize<T>(data: any, ctx: JsonMapperCtx): Set<T> {
    const obj = new Set<T>();

    Object.keys(data).forEach((key) => {
      obj.add(ctx.next(data[key]));
    });

    return obj;
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,4 @@
+import {objectKeys} from "@tsed/core";
 import {JsonMapper} from "../decorators/jsonMapper";
 import {JsonMapperCtx, JsonMapperMethods} from "../interfaces/JsonMapperMethods";
 
@@ -12,7 +13,7 @@
   deserialize<T>(data: any, ctx: JsonMapperCtx): Set<T> {
     const obj = new Set<T>();
 
-    Object.keys(data).forEach((key) => {
+    objectKeys(data).forEach((key) => {
       obj.add(ctx.next(data[key]));
     });
 
```
