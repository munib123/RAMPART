# CrossVul Fix Pair: Uncontrolled Resource Consumption in typescript
**Pair ID:** 4633_8
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4633_8`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```typescript
Lines 1-22 of the vulnerable file.

import {ConverterService, IConverterOptions, JsonSchema, PropertyMetadata} from "@tsed/common";
import {getClass, Store, Type} from "@tsed/core";
import * as mongoose from "mongoose";
import {SchemaDefinition, SchemaTypeOpts} from "mongoose";
import {MONGOOSE_SCHEMA} from "../constants";
import {MongooseSchemaOptions} from "../interfaces";
import {cleanProps} from "./cleanProps";
import {schemaOptions} from "./schemaOptions";

const MONGOOSE_RESERVED_KEYS = ["_id"];

export interface MongooseSchemaMetadata {
  schema: SchemaDefinition;
  virtuals: Map<string, any>;
}

function setUpTarget(target: Type<any>) {
  target.prototype.serialize = function (options: IConverterOptions, converter: ConverterService) {
    const {checkRequiredValue, ignoreCallback, withIgnoredProps = true} = options;

    return converter.serializeClass(this, {
      type: getClass(target),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,10 +1,9 @@
 import {ConverterService, IConverterOptions, JsonSchema, PropertyMetadata} from "@tsed/common";
-import {getClass, Store, Type} from "@tsed/core";
+import {cleanObject, getClass, Store, Type} from "@tsed/core";
 import * as mongoose from "mongoose";
 import {SchemaDefinition, SchemaTypeOpts} from "mongoose";
 import {MONGOOSE_SCHEMA} from "../constants";
 import {MongooseSchemaOptions} from "../interfaces";
-import {cleanProps} from "./cleanProps";
 import {schemaOptions} from "./schemaOptions";
 
 const MONGOOSE_RESERVED_KEYS = ["_id"];
@@ -132,7 +131,7 @@
     schemaTypeOptions = {...schemaTypeOptions, type: getSchema(propertyMetadata.type)};
   }
 
-  schemaTypeOptions = cleanProps({...schemaTypeOptions, ...rawMongooseSchema});
+  schemaTypeOptions = cleanObject({...schemaTypeOptions, ...rawMongooseSchema});
 
   if (propertyMetadata.isCollection) {
     if (propertyMetadata.isArray) {
```
