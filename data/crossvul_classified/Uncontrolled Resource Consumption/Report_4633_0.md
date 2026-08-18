# CrossVul Fix Pair: Uncontrolled Resource Consumption in typescript
**Pair ID:** 4633_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4633_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```typescript
Lines 1-21 of the vulnerable file.

import {Converter} from "../decorators/converter";
import {IConverter, IDeserializer, ISerializer} from "../interfaces/index";

/**
 * Converter component for the `Map` Type.
 * @converters
 * @component
 */
@Converter(Map)
export class MapConverter implements IConverter {
  /**
   *
   * @param data
   * @param target
   * @param baseType
   * @param deserializer
   * @returns {Map<string, T>}
   */
  deserialize<T>(data: any, target: any, baseType: T, deserializer: IDeserializer): Map<string, T> {
    const obj = new Map<string, T>();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,4 @@
+import {objectKeys} from "@tsed/core";
 import {Converter} from "../decorators/converter";
 import {IConverter, IDeserializer, ISerializer} from "../interfaces/index";
 
@@ -19,7 +20,7 @@
   deserialize<T>(data: any, target: any, baseType: T, deserializer: IDeserializer): Map<string, T> {
     const obj = new Map<string, T>();
 
-    Object.keys(data).forEach((key) => {
+    objectKeys(data).forEach((key) => {
       obj.set(key, deserializer(data[key], baseType) as T);
     });
 
```
