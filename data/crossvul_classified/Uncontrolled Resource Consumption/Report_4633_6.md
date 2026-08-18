# CrossVul Fix Pair: Uncontrolled Resource Consumption in typescript
**Pair ID:** 4633_6
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4633_6`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```typescript
Lines 1-21 of the vulnerable file.

import {isArray, isEmpty, isNil, MetadataTypes, nameOf, Type} from "@tsed/core";
import {getPropertiesStores, JsonEntityStore, JsonHookContext, JsonSchema} from "@tsed/schema";
import "../components";
import {JsonMapperContext} from "../domain/JsonMapperContext";
import {getJsonMapperTypes} from "../domain/JsonMapperTypesContainer";
import {JsonMapperMethods} from "../interfaces/JsonMapperMethods";

export interface JsonDeserializerOptions<T = any, C = any> extends MetadataTypes<T, C> {
  /**
   * Types used to map complex types (Symbol, Array, Set, Map)
   */
  types?: Map<Type<any>, JsonMapperMethods>;
  /**
   * useAlias mapping
   */
  useAlias?: boolean;
  /**
   * Accept additionalProperties or ignore it
   */
  additionalProperties?: boolean;
  /**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-import {isArray, isEmpty, isNil, MetadataTypes, nameOf, Type} from "@tsed/core";
+import {isArray, isEmpty, isNil, MetadataTypes, nameOf, objectKeys, Type} from "@tsed/core";
 import {getPropertiesStores, JsonEntityStore, JsonHookContext, JsonSchema} from "@tsed/schema";
 import "../components";
 import {JsonMapperContext} from "../domain/JsonMapperContext";
@@ -77,7 +77,7 @@
   const {type, store = JsonEntityStore.from(type), ...next} = options;
   const propertiesMap = getPropertiesStores(store);
 
-  let keys = Object.keys(src);
+  let keys = objectKeys(src);
   const additionalProperties = propertiesMap.size ? !!store.schema.get("additionalProperties") || options.additionalProperties : true;
   const out: any = new type(src);
 
```
